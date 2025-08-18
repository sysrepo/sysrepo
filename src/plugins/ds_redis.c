/**
 * @file ds_redis.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief internal RedisDB datastore plugin
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

#include <hiredis/hiredis.h>
#include <libyang/libyang.h>

#include "common_db.h"
#include "compat.h"
#include "config.h"
#include "plugins_datastore.h"
#include "sysrepo.h"

#define plugin_name "REDIS DS"

/**
 * IMPORTANT NOTE: While the client sends commands using pipelining, the server will be forced to queue the replies,
 * using memory. So if you need to send a lot of commands with pipelining, it is better to send them as batches each
 * containing a reasonable number, for instance 10k commands, read the replies, and then send another 10k commands
 * again, and so forth. The speed will be nearly the same, but the additional memory used will be at most the amount
 * needed to queue the replies for these 10k commands.
 *
 * source: https://redis.io/docs/latest/develop/use/pipelining/
 *
 */
#define REDIS_MAX_BULK 10000

/**
 * Reply from Redis server containing 50000 elements will require only about 40MB of memory and 50000 elements is big
 * enough to significantly speed up the loading process.
 *
 */
#define REDIS_MAX_AGGREGATE_COUNT "50000"
#define REDIS_MAX_AGGREGATE_LIMIT "2147483648"

/* maximum number of arguments needed to send a command (may be changed) */
#define REDIS_MAX_ARRAY_SIZE 32

/* context should be different for each thread */
typedef struct redis_thread_data_s {
    redisContext *ctx; /* Redis context */
    pthread_t id; /* unique thread id */
} redis_thread_data_t;

/* pool of connections */
typedef struct redis_plg_conn_data_s {
    pthread_rwlock_t lock; /* connection lock */
    redis_thread_data_t *conn_pool; /* pool of connections to Redis database */
    uint32_t size; /* size of pool */
} redis_plg_conn_data_t;

/* holds number of commands sent to pipeline */
typedef struct redis_bulk_s {
    uint32_t count; /* number of commands sent to pipeline */
} redis_bulk_t;

/* holds arguments necessary for a command */
typedef struct redis_argv_s {
    int argc;                                /* number of arguments */
    char *argv[REDIS_MAX_ARRAY_SIZE];        /* arguments */
    size_t argvlen[REDIS_MAX_ARRAY_SIZE];    /* argument lengths */
    int is_allocated[REDIS_MAX_ARRAY_SIZE];  /* whether the argument is dynamically allocated or not */
} redis_argv_t;

/* holds types of Redis replies to check */
typedef enum redis_flags_e {
    CHCK_ERR = 0x1, /* check whether the reply is not of error type */
    CHCK_ARR = 0x2  /* check whether the reply is of array type */
} redis_flags_t;

/**
 * @brief Get the prefix for the given datastore.
 *
 * @param[in] ds Given datastore.
 * @return Prefix or NULL if datastore is not supported.
 */
static const char *
srpds_ds2dsprefix(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_STARTUP:
        return "sr:startup";
    case SR_DS_RUNNING:
        return "sr:running";
    case SR_DS_CANDIDATE:
        return "sr:candidate";
    case SR_DS_OPERATIONAL:
        return "sr:operational";
    case SR_DS_FACTORY_DEFAULT:
        return "sr:factory-default";
    default:
        return NULL;
    }
}

/**
 * @brief Execute a bulk operation (check replies).
 *
 * @param[in] ctx Redis context.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_exec(redisContext *ctx, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    uint32_t i;

    for (i = 0; i < bulk->count; ++i) {
        if (redisGetReply(ctx, (void **)&reply) != REDIS_OK) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisGetReply()", "");
            goto cleanup;
        }

        if (!reply) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisGetReply()", "");
            goto cleanup;
        }

        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisGetReply()", reply->str);
            goto cleanup;
        }
        freeReplyObject(reply);
        reply = NULL;
    }

    bulk->count = 0;

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Send a query to the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] flag Flags to check upon reply.
 * @param[out] out Reply from the database (can be NULL).
 * @param[in] format Query format.
 * @param ... Format arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_query(redisContext *ctx, int flag, redisReply **out, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    va_list args;

    va_start(args, format);

    reply = redisvCommand(ctx, format, args);

    /* save reply */
    if (out) {
        *out = reply;
    }

    /* check reply */
    if (!reply) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisvCommand()", "");
        goto cleanup;
    }

    switch (flag) {
    case CHCK_ERR:
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisvCommand()", reply->str);
            goto cleanup;
        }
        break;
    case CHCK_ARR:
        if (reply->type != REDIS_REPLY_ARRAY) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisvCommand()", "No reply array");
            goto cleanup;
        }
        break;
    }

cleanup:
    if (!out) {
        freeReplyObject(reply);
    }
    va_end(args);
    return err_info;
}

/**
 * @brief Send a query to the database without waiting for the reply.
 *
 * @param[in] ctx Redis context.
 * @param[out] bulk Bulk to use.
 * @param[in] format Query format.
 * @param ... Format arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_query(redisContext *ctx, redis_bulk_t *bulk, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list args;

    va_start(args, format);

    /* send command */
    if (redisvAppendCommand(ctx, format, args) != REDIS_OK) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisvAppendCommand()", "Wrong arguments");
        goto cleanup;
    }
    ++bulk->count;

    /* check replies if there are too many */
    if (bulk->count >= REDIS_MAX_BULK) {
        if ((err_info = srpds_bulk_exec(ctx, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    va_end(args);
    return err_info;
}

/**
 * @brief Send a query to the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] argv Arguments.
 * @param[in] flag Flags to check upon reply.
 * @param[out] out Reply from the database (can be NULL).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_query_argv(redisContext *ctx, redis_argv_t *argv, int flag, redisReply **out)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    reply = redisCommandArgv(ctx, argv->argc, (const char **)argv->argv, (const size_t *)argv->argvlen);

    /* save reply */
    if (out) {
        *out = reply;
    }

    /* check reply */
    if (!reply) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisCommandArgv()", "");
        goto cleanup;
    }

    switch (flag) {
    case CHCK_ERR:
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisCommandArgv()", reply->str);
            goto cleanup;
        }
        break;
    case CHCK_ARR:
        if (reply->type != REDIS_REPLY_ARRAY) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisCommandArgv()", "No reply array");
            goto cleanup;
        }
        break;
    }

cleanup:
    if (!out) {
        freeReplyObject(reply);
    }
    return err_info;
}

/**
 * @brief Send a query to the database without waiting for the reply.
 *
 * @param[in] ctx Redis context.
 * @param[in] argv Arguments.
 * @param[in] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_query_argv(redisContext *ctx, redis_argv_t *argv, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (redisAppendCommandArgv(ctx, argv->argc, (const char **)argv->argv, (const size_t *)argv->argvlen) !=
            REDIS_OK) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisAppendCommandArgv()", "Wrong arguments");
        goto cleanup;
    }
    ++bulk->count;

    if (bulk->count >= REDIS_MAX_BULK) {
        if ((err_info = srpds_bulk_exec(ctx, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Initialize plugin connection data.
 *
 * @param[in,out] pdata Plugin connection data.
 * @param[out] ctx Retrieved Redis context.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_data_init(redis_plg_conn_data_t *pdata, redisContext **ctx)
{
    sr_error_info_t *err_info = NULL;
    redisContext *rds_ctx = NULL;
    redisReply *reply = NULL;
    redis_thread_data_t *new_pool = NULL;
    int found = 0;

    *ctx = NULL;

    /* PLUGIN DATA RDLOCK */
    pthread_rwlock_rdlock(&pdata->lock);

    /* find redis context in the existing connection */
    for (uint32_t i = 0; i < pdata->size; ++i) {
        if (pdata->conn_pool[i].id == pthread_self()) {
            *ctx = pdata->conn_pool[i].ctx;
            found = 1;
            break;
        }
    }

    /* PLUGIN DATA UNLOCK */
    pthread_rwlock_unlock(&pdata->lock);

    if (!found) {
        /* context not found, so create one */
        rds_ctx = redisConnect(SR_DS_PLG_REDIS_HOST, SR_DS_PLG_REDIS_PORT);
        if ((rds_ctx == NULL) || rds_ctx->err) {
            if (rds_ctx) {
                ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisConnect()", rds_ctx->errstr);
                goto cleanup;
            } else {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "redisConnect()",
                        "Could not allocate Redis context");
                goto cleanup;
            }
        }

        /* authenticate if needed */
        if (strlen(SR_DS_PLG_REDIS_USERNAME)) {
            if ((err_info = srpds_query(rds_ctx, 0, &reply,
                    "AUTH " SR_DS_PLG_REDIS_USERNAME " " SR_DS_PLG_REDIS_PASSWORD))) {
                goto cleanup;
            }
            if (reply->type == REDIS_REPLY_ERROR) {
                ERRINFO(&err_info, plugin_name, SR_ERR_UNAUTHORIZED, "Authentication", reply->str);
                goto cleanup;
            }
        }

        /* PLUGIN DATA WRLOCK */
        pthread_rwlock_wrlock(&pdata->lock);

        new_pool = realloc(pdata->conn_pool, (sizeof *new_pool) * (pdata->size + 1));
        if (!new_pool) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "realloc()", "");

            /* PLUGIN DATA UNLOCK */
            pthread_rwlock_unlock(&pdata->lock);

            goto cleanup;
        }

        pdata->conn_pool = new_pool;
        pdata->conn_pool[pdata->size].ctx = rds_ctx;
        pdata->conn_pool[pdata->size].id = pthread_self();
        pdata->size = pdata->size + 1;
        *ctx = rds_ctx;

        /* PLUGIN DATA UNLOCK */
        pthread_rwlock_unlock(&pdata->lock);

        /* set necessary configuration */
        if ((err_info = srpds_query(*ctx, CHCK_ERR, NULL, "FT.CONFIG SET MAXAGGREGATERESULTS -1"))) {
            goto cleanup;
        }

        if ((err_info = srpds_query(*ctx, CHCK_ERR, NULL,
                "FT.CONFIG SET MAXEXPANSIONS " REDIS_MAX_AGGREGATE_LIMIT))) {
            goto cleanup;
        }
    }

cleanup:
    if (err_info && rds_ctx) {
        redisFree(rds_ctx);
    }
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Get data prefix.
 *
 * @param[in] ds Given datastore.
 * @param[in] module_name Given module name.
 * @param[in] cid Connection ID, for @p ds ::SR_DS_OPERATIONAL.
 * @param[in] sid Session ID, for @p ds ::SR_DS_OPERATIONAL.
 * @param[out] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_mod_ns(sr_datastore_t ds, const char *module_name, sr_cid_t cid, uint32_t sid, char **mod_ns)
{
    sr_error_info_t *err_info = NULL;
    int r;

    if ((ds == SR_DS_OPERATIONAL) && cid && sid) {
        r = asprintf(mod_ns, "%s:%s:%s+%" PRIu32 "+%" PRIu32, srpds_ds2dsprefix(ds), sr_get_shm_prefix(), module_name,
                cid, sid);
    } else {
        r = asprintf(mod_ns, "%s:%s:%s", srpds_ds2dsprefix(ds), sr_get_shm_prefix(), module_name);
    }

    if (r == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
    }
    return err_info;
}

/**
 * @brief Get module owner, group and permissions from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] owner Module owner.
 * @param[out] group Module group.
 * @param[out] perm Module permissions.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_access(redisContext *ctx, const char *mod_ns, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    if (owner) {
        *owner = NULL;
    }
    if (group) {
        *group = NULL;
    }
    if (perm) {
        *perm = 0;
    }

    /* get the owner */
    if (owner) {
        if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:perm:owner", mod_ns))) {
            goto cleanup;
        }
        *owner = strdup(reply->str);
        if (!*owner) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
            goto cleanup;
        }
        freeReplyObject(reply);
        reply = NULL;
    }

    /* get the group */
    if (group) {
        if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:perm:group", mod_ns))) {
            goto cleanup;
        }
        *group = strdup(reply->str);
        if (!*group) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "strdup()", strerror(errno));
            goto cleanup;
        }
        freeReplyObject(reply);
        reply = NULL;
    }

    /* get the permissions */
    if (perm) {
        if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:perm:perm", mod_ns))) {
            goto cleanup;
        }
        *perm = (unsigned int)strtoll(reply->str, NULL, 0);
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
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Add a new argument to the structure.
 *
 * @param[out] argv Structure of arguments.
 * @param[in] str Argument.
 * @param[in] len Argument length.
 */
static void
srpds_argv_add(redis_argv_t *argv, const char *str, size_t len)
{
    argv->argv[argv->argc] = (char *)str;
    argv->argvlen[argv->argc] = len;
    argv->is_allocated[argv->argc] = 0;
    ++argv->argc;
}

/**
 * @brief Add a new argument to the structure using format.
 *
 * @param[out] argv Structure of arguments.
 * @param[in] format Argument format.
 * @param ... Format arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_argv_add_format(redis_argv_t *argv, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    char *str = NULL;
    va_list args;

    va_start(args, format);

    if (vasprintf(&str, format, args) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "vasprintf()", strerror(errno));
        goto cleanup;
    }

    va_end(args);

    argv->argv[argv->argc] = str;
    argv->argvlen[argv->argc] = strlen(str);
    argv->is_allocated[argv->argc] = 1;
    ++argv->argc;

cleanup:
    if (err_info) {
        free(str);
    }
    return err_info;
}

/**
 * @brief Destroy argument structure. Free arguments.
 *
 * @param[out] argv Argument structure to destroy.
 */
static void
srpds_argv_destroy(redis_argv_t *argv)
{
    int i;

    for (i = 0; i < argv->argc; ++i) {
        if (argv->is_allocated[i]) {
            free(argv->argv[i]);
        }
    }
    argv->argc = 0;
}

/**
 * @brief Put all load XPaths into a query filter.
 *
 * @param[in] ctx Libyang context.
 * @param[in] xpaths Array of XPaths.
 * @param[in] xpath_cnt XPath count.
 * @param[in] oper_ds Flag if the filter is for loading operational data and special handling is needed.
 * @param[out] xpath_filter Final query filter.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_process_load_paths(struct ly_ctx *ctx, const char **xpaths, uint32_t xpath_cnt, int oper_ds, char **xpath_filter)
{
    sr_error_info_t *err_info = NULL;
    uint32_t i;
    char *tmp = NULL, *path = NULL, *escaped_path = NULL;
    struct lyd_node *ctx_node = NULL, *match = NULL;
    uint32_t log_options = 0, *old_options;
    LY_ERR lyrc;

    *xpath_filter = NULL;

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
        }

        /* path is key */
        if (lysc_is_key(lys_find_path(ctx, NULL, path, 0))) {
            srpds_get_parent_path(path);
        }

        if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped_path))) {
            goto cleanup;
        }

        /* start prefix match */
        if (i == 0) {
            if (asprintf(&tmp, "%s*", escaped_path) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            /* continue prefix match */
        } else {
            if (asprintf(&tmp, "%s | %s*", *xpath_filter, escaped_path) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
        }
        free(*xpath_filter);
        *xpath_filter = tmp;
        free(escaped_path);
        escaped_path = NULL;

        /* add all parent paths also */
        srpds_get_parent_path(path);
        while (path[0] != '\0') {
            /* continue with exact match (for parent nodes) */
            if ((err_info = srpds_escape_string(plugin_name, path, '\\', &escaped_path))) {
                goto cleanup;
            }
            if (asprintf(&tmp, "%s | %s", *xpath_filter, escaped_path) == -1) {
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
                goto cleanup;
            }
            free(*xpath_filter);
            *xpath_filter = tmp;
            free(escaped_path);
            escaped_path = NULL;

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
        if (asprintf(&tmp, "%s | %s*", *xpath_filter, escaped_path) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        free(*xpath_filter);
        *xpath_filter = tmp;
    }

cleanup:
    if (err_info) {
        free(*xpath_filter);
    }
    free(path);
    free(escaped_path);
    lyd_free_all(ctx_node);
    return err_info;
}

/**
 * @brief Load all data (only :data) and store them inside the lyd_node structure (for all datastores).
 *
 * @param[in] ctx Redis context.
 * @param[in] mod Given module.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] xpath_filter Query filter composed of load XPaths to speed up the loading process.
 * @param[out] mod_data Retrieved module data from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_all(redisContext *ctx, const struct lys_module *mod, sr_datastore_t ds, const char *mod_ns,
        const char *xpath_filter, struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    uint64_t valtype = 0, order = 0;
    const char *path, *name, *module_name = NULL, *value = NULL, *path_no_pred = NULL;
    enum srpds_db_ly_types type;
    int dflt_flag = 0;
    char **keys = NULL;
    uint32_t *lengths = NULL;
    int32_t meta_count = 0;
    const char *meta_name = NULL, *meta_value = NULL;
    srpds_db_userordered_lists_t uo_lists = {0};
    struct lyd_node **parent_nodes = NULL;
    size_t pnodes_size = 0;

    uint32_t i, j;
    redisReply *reply = NULL, *partial = NULL;
    long long cursor;
    redis_argv_t argv = {0};

    /*
    *   Loading multiple different sets of data
    *
    *   Load All Datastores
    *   | 1) containers (LYS_CONTAINER)
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | m_path_modif | n_meta_count | {metadata} ]
    *   |
    *   | 2) lists (LYS_LIST)
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | f_keys | m_path_modif | n_meta_count | {metadata} ]
    *   |
    *   | 3) leafs and leaf-lists (LYS_LEAF and LYS_LEAFLIST)
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | e_dflt_flag | g_value | m_path_modif | n_meta_count
    *   |            | {metadata} ]
    *   |
    *   | 4) anydata and anyxml (LYS_ANYDATA and LYS_ANYXML)
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | e_dflt_flag | g_value | h_valtype | m_path_modif
    *   |            | n_meta_count | {metadata} ]
    *   |
    *   | 5) user-ordered lists
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | f_keys | i_order | j_path_no_pred | k_prev
    *   |            | l_is_prev_empty | m_path_modif | n_meta_count | {metadata} ]
    *   |
    *   | 6) user-ordered leaf-lists
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | e_dflt_flag | g_value | i_order | j_path_no_pred
    *   |            | k_prev | l_is_prev_empty | m_path_modif | n_meta_count | {metadata} ]
    *   |
    *   | 7) opaque nodes
    *   |    Dataset [ a_path | b_name | c_type | d_module_name | g_value | m_path_modif | n_attr_count
    *   |            | {attributes} ]
    *   |
    *   | 8) other metadata (glob: and meta:)
    *   |
    *   | start number defines the type (1 - container, 2 - list...)
    *   | field names are prefixed with a letter so that they can be quickly identified based on this letter
    *   | module_name = "" - use parent's module | name - use the module specified by this name
    *   | valtype     = 0 - XML | 1 - JSON
    *   | {metadata}  = meta_count number of fields containing metadata of the node
    *
    *   Metadata and MaxOrder
    *   | 1) global metadata
    *   |     1.1) glob:last-modified-sec | glob:last-modified-nsec = timestamp (last-modif) [ !!! NOT LOADED ]
    *   |     1.2) glob:candidate-modified = is different from running? (for candidate datastore) [ !!! NOT LOADED ]
    *   |     1.3) glob:perm = owner, group and permissions [ !!! NOT LOADED ]
    *   |    Dataset [ value ]
    *   |
    *   | 2) maximum order for a userordered list or leaflist
    *   |     2.1) meta:[path] = maximum order [ !!! NOT LOADED ]
    *   |    Dataset [ value ]
    *
    *   [ !!! NOT LOADED ] data are only for internal use
    */

    /* results are limited to REDIS_MAX_AGGREGATE_LIMIT */
    /* use FT.AGGREGATE since FT.SEARCH cannot retrieve results gradually (no WITHCURSOR option) */
    srpds_argv_add(&argv, "FT.AGGREGATE", 12);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data", mod_ns))) {
        goto cleanup;
    }
    if (xpath_filter) {
        if ((err_info = srpds_argv_add_format(&argv, "@a_path:{%s}", xpath_filter))) {
            goto cleanup;
        }
    } else {
        srpds_argv_add(&argv, "*", 1);
    }
    srpds_argv_add(&argv, "SORTBY", 6);
    srpds_argv_add(&argv, "2", 1);
    srpds_argv_add(&argv, "@m_path_modif", 13);
    srpds_argv_add(&argv, "ASC", 3);
    srpds_argv_add(&argv, "LOAD", 4);
    srpds_argv_add(&argv, "*", 1);
    srpds_argv_add(&argv, "LIMIT", 5);
    srpds_argv_add(&argv, "0", 1);
    srpds_argv_add(&argv, REDIS_MAX_AGGREGATE_LIMIT, strlen(REDIS_MAX_AGGREGATE_LIMIT));
    srpds_argv_add(&argv, "WITHCURSOR", 10);
    srpds_argv_add(&argv, "COUNT", 5);
    srpds_argv_add(&argv, REDIS_MAX_AGGREGATE_COUNT, strlen(REDIS_MAX_AGGREGATE_COUNT));

    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ARR, &reply))) {
        goto cleanup;
    }

    while (1) {
        for (i = 1; i < reply->element[0]->elements; ++i) {
            partial = reply->element[0]->element[i];

            for (j = 0; j < partial->elements; j += 2) {
                switch (partial->element[j]->str[0]) {
                case 'a':
                    /* get path */
                    path = partial->element[j + 1]->str;
                    break;
                case 'b':
                    /* get name */
                    name = partial->element[j + 1]->str;
                    break;
                case 'c':
                    /* get type */
                    type = (uint64_t)strtoull(partial->element[j + 1]->str, NULL, 0);
                    break;
                case 'd':
                    /* get module_name */
                    module_name = partial->element[j + 1]->str;
                    break;
                case 'e':
                    /* get dflt_flag */
                    dflt_flag = (uint64_t)strtoull(partial->element[j + 1]->str, NULL, 0);
                    break;
                case 'f':
                    /* get keys */
                    value = partial->element[j + 1]->str;
                    if ((err_info = srpds_parse_keys(plugin_name, value, &keys, &lengths))) {
                        goto cleanup;
                    }
                    break;
                case 'g':
                    /* get value */
                    value = partial->element[j + 1]->str;
                    break;
                case 'h':
                    /* get valtype */
                    valtype = (uint64_t)strtoull(partial->element[j + 1]->str, NULL, 0);
                    break;
                case 'i':
                    order = (uint64_t)strtoull(partial->element[j + 1]->str, NULL, 0);
                    break;
                case 'j':
                    path_no_pred = partial->element[j + 1]->str;
                    break;
                case 'k':
                case 'l':
                case 'm':
                    /* skip */
                    break;
                case 'n':
                    meta_count = (int32_t)strtoll(partial->element[j + 1]->str, NULL, 0);
                    break;
                case 'y':
                    /* get meta name */
                    meta_name = partial->element[j + 1]->str;
                    break;
                case 'z':
                    /* get meta value */
                    meta_value = partial->element[j + 1]->str;
                    break;
                default:
                    ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Loading", "Unsupported type of field");
                    goto cleanup;
                }
            }

            /* add a new node to mod_data */
            if ((err_info = srpds_add_mod_data(plugin_name, mod->ctx, ds, path, name, type, module_name, value,
                    valtype, &dflt_flag, (const char **)keys, lengths, order, path_no_pred, meta_count, meta_name,
                    meta_value, &uo_lists, &parent_nodes, &pnodes_size, mod_data))) {
                goto cleanup;
            }
            free(keys);
            free(lengths);
            keys = NULL;
            lengths = NULL;
        }

        cursor = reply->element[1]->integer;
        if (cursor == 0) {
            break;
        }
        freeReplyObject(reply);
        reply = NULL;

        if ((err_info = srpds_query(ctx, CHCK_ARR, &reply,
                "FT.CURSOR READ %s:data %d COUNT " REDIS_MAX_AGGREGATE_COUNT, mod_ns, cursor))) {
            goto cleanup;
        }
    }

    /* go through all userordered lists and leaflists and order them */
    if ((err_info = srpds_order_uo_lists(plugin_name, &uo_lists))) {
        goto cleanup;
    }

    *mod_data = lyd_first_sibling(*mod_data);

cleanup:
    free(keys);
    free(lengths);
    free(parent_nodes);
    srpds_cleanup_uo_lists(&uo_lists);
    srpds_argv_destroy(&argv);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Add metadata to the arguments to store in the database.
 *
 * @param[in] meta Metadata to store.
 * @param[in] argv Arguments to append metadata to.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_meta(const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;
    const char *meta_value = NULL;
    int32_t meta_count = srpds_get_meta_count(meta);

    /* store the number of metadata */
    srpds_argv_add(argv, "n_meta_count", 12);
    if ((err_info = srpds_argv_add_format(argv, "%d", meta_count))) {
        goto cleanup;
    }

    /* we are only expecting zero or one metadata (origin) */
    while (meta_count && meta) {
        /* skip yang: and sysrepo: metadata, this is libyang and sysrepo specific data */
        if (strcmp(meta->annotation->module->name, "yang") && strcmp(meta->annotation->module->name, "sysrepo")) {
            /* get meta value */
            meta_value = lyd_get_meta_value(meta);

            /* store metadata */
            srpds_argv_add(argv, "y_meta_name", 11);
            if ((err_info = srpds_argv_add_format(argv, "%s:%s", meta->annotation->module->name, meta->name))) {
                goto cleanup;
            }
            srpds_argv_add(argv, "z_meta_value", 12);
            srpds_argv_add(argv, meta_value, strlen(meta_value));

            /* we found origin, break */
            break;
        }
        meta = meta->next;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new container.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_container(const char *mod_ns, const char *path, const char *name, const char *module_name,
        const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_CONTAINER))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new list instance.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] keys Keys of the list instance.
 * @param[in] keys_length Length of @p keys.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_list(const char *mod_ns, const char *path, const char *name, const char *module_name, const char *keys,
        uint32_t keys_length, const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_LIST))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "f_keys", 6);
    srpds_argv_add(argv, keys, keys_length);
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new leaf/leaflist instance.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] dflt_flag Default flag of the node.
 * @param[in] value Value of the node.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_term(const char *mod_ns, const char *path, const char *name, const char *module_name, int dflt_flag,
        const char *value, const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_TERM))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "e_dflt_flag", 11);
    if ((err_info = srpds_argv_add_format(argv, "%d", dflt_flag))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "g_value", 7);
    srpds_argv_add(argv, value, value ? strlen(value) : 0);
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new anydata/anyxml node.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (LYD_ANYDATA_XML = 0; LYD_ANYDATA_JSON = 1)
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_any(const char *mod_ns, const char *path, const char *name, const char *module_name, const char *value,
        int32_t valtype, const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_ANY))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "g_value", 7);
    srpds_argv_add(argv, value, value ? strlen(value) : 0);
    srpds_argv_add(argv, "h_valtype", 9);
    if ((err_info = srpds_argv_add_format(argv, "%" PRId32, valtype))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new userordered list instance.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] keys Keys of the list instance.
 * @param[in] keys_length Length of @p keys.
 * @param[in] order Order of the node.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in] prev_pred Predicate of the previous node.
 * @param[in] is_prev_empty Whether @p prev_pred is empty.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_list_uo(const char *mod_ns, const char *path, const char *name, const char *module_name, const char *keys,
        uint32_t keys_length, uint64_t order, const char *path_no_pred, const char *prev_pred, int is_prev_empty,
        const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_LIST_UO))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "f_keys", 6);
    srpds_argv_add(argv, keys, keys_length);
    srpds_argv_add(argv, "i_order", 7);
    if ((err_info = srpds_argv_add_format(argv, "%" PRIu64, order))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "j_path_no_pred", 14);
    srpds_argv_add(argv, path_no_pred, strlen(path_no_pred));
    srpds_argv_add(argv, "k_prev", 6);
    srpds_argv_add(argv, prev_pred, prev_pred ? strlen(prev_pred) : 0);
    srpds_argv_add(argv, "l_is_prev_empty", 15);
    if ((err_info = srpds_argv_add_format(argv, "%d", is_prev_empty))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new userordered leaflist instance.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] dflt_flag Default flag of the node.
 * @param[in] value Value of the node.
 * @param[in] order Order of the node.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in] prev_pred Predicate of the previous node.
 * @param[in] is_prev_empty Whether @p prev_pred is empty.
 * @param[in] path_modif Modified path.
 * @param[in] meta Metadata of the node.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_leaflist_uo(const char *mod_ns, const char *path, const char *name, const char *module_name, int dflt_flag,
        const char *value, uint64_t order, const char *path_no_pred, const char *prev_pred, int is_prev_empty,
        const char *path_modif, const struct lyd_meta *meta, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_LEAFLIST_UO))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "e_dflt_flag", 11);
    if ((err_info = srpds_argv_add_format(argv, "%d", dflt_flag))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "g_value", 7);
    srpds_argv_add(argv, value, value ? strlen(value) : 0);
    srpds_argv_add(argv, "i_order", 7);
    if ((err_info = srpds_argv_add_format(argv, "%" PRIu64, order))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "j_path_no_pred", 14);
    srpds_argv_add(argv, path_no_pred, strlen(path_no_pred));
    srpds_argv_add(argv, "k_prev", 6);
    srpds_argv_add(argv, prev_pred, prev_pred ? strlen(prev_pred) : 0);
    srpds_argv_add(argv, "l_is_prev_empty", 15);
    if ((err_info = srpds_argv_add_format(argv, "%d", is_prev_empty))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    if ((err_info = srpds_add_meta(meta, argv))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Get arguments for a new opaque node.
 *
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of the data node.
 * @param[in] name Name of the data node.
 * @param[in] module_name Name of the node module.
 * @param[in] value Value of the node.
 * @param[in] path_modif Modified path.
 * @param[out] argv Arguments for command.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_opaque(const char *mod_ns, const char *path, const char *name, const char *module_name, const char *value,
        const char *path_modif, redis_argv_t *argv)
{
    sr_error_info_t *err_info = NULL;

    /* add arguments for command */
    srpds_argv_add(argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(argv, "%s:data:%s$%s", mod_ns, path, value))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "a_path", 6);
    srpds_argv_add(argv, path, strlen(path));
    srpds_argv_add(argv, "b_name", 6);
    srpds_argv_add(argv, name, strlen(name));
    srpds_argv_add(argv, "c_type", 6);
    if ((err_info = srpds_argv_add_format(argv, "%d", SRPDS_DB_LY_OPAQUE))) {
        goto cleanup;
    }
    srpds_argv_add(argv, "d_module_name", 13);
    srpds_argv_add(argv, module_name, module_name ? strlen(module_name) : 0);
    srpds_argv_add(argv, "g_value", 7);
    srpds_argv_add(argv, value, value ? strlen(value) : 0);
    srpds_argv_add(argv, "m_path_modif", 12);
    srpds_argv_add(argv, path_modif, strlen(path_modif));
    srpds_argv_add(argv, "n_attr_count", 12);
    srpds_argv_add(argv, "0", 1);

cleanup:
    return err_info;
}

/**
 * @brief Delete all metadata fields of an element in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to the node with metadata.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_meta(redisContext *ctx, const char *mod_ns, const char *path, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;

    /* delete origin metadata */
    if (bulk) {
        if ((err_info = srpds_bulk_query(ctx, bulk, "HDEL %s:data:%s y_meta_name z_meta_value", mod_ns, path))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_query(ctx, CHCK_ERR, NULL, "HDEL %s:data:%s y_meta_name z_meta_value", mod_ns,
                path))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Update the maximum order of a list or a leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] max_order Maximum order to store.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_maxord(redisContext *ctx, const char *mod_ns, const char *path_no_pred, uint64_t max_order)
{
    sr_error_info_t *err_info = NULL;

    /* update only if max_order has been changed
     * aka is different from zero */
    if (max_order) {
        /* update maximum order of the list */
        if ((err_info = srpds_query(ctx, CHCK_ERR, NULL, "HSET %s:meta:%s value %" PRIu64, mod_ns,
                path_no_pred, max_order))) {
            goto cleanup;
        }
    }

cleanup:
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
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] out_max_order Retrieved maximum order from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_get_maxord(redisContext *ctx, const char *mod_ns, const char *path_no_pred, uint64_t *out_max_order)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    if (*out_max_order == 0) {
        /* get maximum order of the list */
        if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "HGET %s:meta:%s value", mod_ns, path_no_pred))) {
            goto cleanup;
        }

        *out_max_order = (uint64_t)strtoull(reply->str, NULL, 0);
    }

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Get the order of the previous element in a list or a leaf-list from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] prev_pred Predicate of the previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_prev(redisContext *ctx, const char *mod_ns, const char *prev_pred, const char *path_no_pred,
        uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "HGET %s:data:%s%s i_order", mod_ns, path_no_pred,
            prev_pred))) {
        goto cleanup;
    }

    *order = (uint64_t)strtoull(reply->str, NULL, 0);

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Get the order of the next element in a list or a leaf-list from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] prev_pred Predicate of the next element's previous element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[out] order Order of the next element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_next(redisContext *ctx, const char *mod_ns, const char *prev_pred, const char *path_no_pred,
        uint64_t *order)
{
    /* number of arguments for the query is predetermined - 6 */
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    redis_argv_t argv = {0};
    char *prev_escaped = NULL, *path_no_pred_escaped = NULL;

    *order = 0;

    /* escape all special characters so that query is valid */
    if ((err_info = srpds_escape_string(plugin_name, prev_pred, '\\', &prev_escaped))) {
        goto cleanup;
    }
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, '\\', &path_no_pred_escaped))) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "FT.AGGREGATE", 12);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data", mod_ns))) {
        goto cleanup;
    }

    /* we need is_prev_empty field since we cannot check if prev is empty or not */
    if (prev_pred[0] == '\0') {
        if ((err_info = srpds_argv_add_format(&argv, "@l_is_prev_empty:[1 1] @j_path_no_pred:{%s}",
                path_no_pred_escaped))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_argv_add_format(&argv, "@k_prev:{%s} @j_path_no_pred:{%s}", prev_escaped,
                path_no_pred_escaped))) {
            goto cleanup;
        }
    }

    /* retrieve only order */
    srpds_argv_add(&argv, "LOAD", 4);
    srpds_argv_add(&argv, "1", 1);
    srpds_argv_add(&argv, "i_order", 7);

    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ARR, &reply))) {
        goto cleanup;
    }

    /* the only retrieved field is order
     * on [0] is the number of retrieved elements, on [1] is the retrieved element
     * on [0] is the name of the field, on [1] is the value of the field
     * [1] -> [1] - retrieved element's value */
    if (reply->elements == 2) {
        *order = (uint64_t)strtoull(reply->element[1]->element[1]->str, NULL, 0);
    }

cleanup:
    free(prev_escaped);
    free(path_no_pred_escaped);
    srpds_argv_destroy(&argv);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief If there is only one point order gap between elements where newly created element
 *          should be placed, shifting has to be done, e.g. 1  3  {4}   [5]  8  13
 *                                                                    *
 *                                                                    |
 *                                                                new element
 *                                                                    |
 *                                                                    *
 *                                                          1  3  {4} 5 [6]  8  13
 * @param[in] ctx Redis context
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] next_elem_order Order of the next element.
 * @param[out] max_order Changed maximum order (shifting can change maximum order).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_shift_uo_list_recursively(redisContext *ctx, const char *mod_ns, const char *path_no_pred,
        uint64_t next_elem_order, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    redis_argv_t argv = {0};
    char *path_no_pred_escaped = NULL;

    if ((err_info = srpds_get_maxord(ctx, mod_ns, path_no_pred, max_order))) {
        goto cleanup;
    }

    /* in case of overflow, update maxorder */
    if (*max_order < next_elem_order) {
        *max_order = next_elem_order;
    }

    /* escape all special characters so that query is valid */
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, '\\', &path_no_pred_escaped))) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "FT.AGGREGATE", 12);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_argv_add_format(&argv, "@i_order:[%" PRIu64 " %" PRIu64 "] @j_path_no_pred:{%s}",
            next_elem_order, next_elem_order, path_no_pred_escaped))) {
        goto cleanup;
    }

    /* retrieve only key */
    srpds_argv_add(&argv, "LOAD", 4);
    srpds_argv_add(&argv, "1", 1);
    srpds_argv_add(&argv, "__key", 5);

    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ARR, &reply))) {
        goto cleanup;
    }

    if (reply->element[0]->integer == 1) {
        /* An element with such order has been found, shift all elements
         * after this element */
        if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_elem_order + 1, max_order))) {
            goto cleanup;
        }

        /* on [1] -> [1] is the key of the found element */
        if ((err_info = srpds_query(ctx, CHCK_ERR, NULL, "HSET %s i_order %" PRIu64,
                reply->element[1]->element[1]->str, next_elem_order + 1))) {
            goto cleanup;
        }
    }

cleanup:
    free(path_no_pred_escaped);
    srpds_argv_destroy(&argv);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Change the next element in the list or leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] prev_pred Predicate of a previous element.
 * @param[in] new_prev_pred New predicate to be set.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_change_next_element(redisContext *ctx, const char *mod_ns, const char *path_no_pred, const char *prev_pred,
        const char *new_prev_pred)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    redis_argv_t argv = {0};
    char *prev_escaped = NULL, *path_no_pred_escaped = NULL;

    if ((err_info = srpds_escape_string(plugin_name, prev_pred, '\\', &prev_escaped))) {
        goto cleanup;
    }
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, '\\', &path_no_pred_escaped))) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "FT.AGGREGATE", 12);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data", mod_ns))) {
        goto cleanup;
    }

    /* we need is_prev_empty field since we cannot check if prev is empty or not */
    if (prev_pred[0] == '\0') {
        if ((err_info = srpds_argv_add_format(&argv, "@l_is_prev_empty:[1 1] @j_path_no_pred:{%s}",
                path_no_pred_escaped))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_argv_add_format(&argv, "@k_prev:{%s} @j_path_no_pred:{%s}", prev_escaped,
                path_no_pred_escaped))) {
            goto cleanup;
        }
    }
    srpds_argv_add(&argv, "LOAD", 4);
    srpds_argv_add(&argv, "1", 1);
    srpds_argv_add(&argv, "__key", 5);

    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ARR, &reply))) {
        goto cleanup;
    }

    /* change the next element */
    if (reply->elements == 2) {
        if ((err_info = srpds_query(ctx, CHCK_ERR, NULL, "HSET %s k_prev %s l_is_prev_empty %d",
                reply->element[1]->element[1]->str, new_prev_pred, (new_prev_pred[0] == '\0') ? 1 : 0))) {
            goto cleanup;
        }
    }

cleanup:
    free(prev_escaped);
    free(path_no_pred_escaped);
    srpds_argv_destroy(&argv);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Prepare the insertion/update of a user-ordered element in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] prev Value of the node before this node.
 * @param[out] max_order Changed maximum order.
 * @param[out] order Order to use for insert/update.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_prepare_create_uo_op(redisContext *ctx, const char *mod_ns, const char *path_no_pred, const char *predicate,
        const char *prev, uint64_t *max_order, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    uint64_t prev_order = 0, next_order = 0;

    /* there is a previous element */
    if (strcmp(prev, "")) {
        /* load previous,
         * get order of the previous element */
        if ((err_info = srpds_load_prev(ctx, mod_ns, prev, path_no_pred, &prev_order))) {
            goto cleanup;
        }

        /* load next
         * get order of the next element */
        if ((err_info = srpds_load_next(ctx, mod_ns, prev, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* get max order for lists and leaf-lists */
            if ((err_info = srpds_get_maxord(ctx, mod_ns, path_no_pred, max_order))) {
                goto cleanup;
            }

            srpds_inc_maxord(max_order);

            *order = *max_order;
        } else if (next_order - prev_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev, predicate))) {
                goto cleanup;
            }

            *order = next_order;
        } else {
            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev, predicate))) {
                goto cleanup;
            }

            *order = (uint64_t)(prev_order + (next_order - prev_order) / 2);
        }
        /* there is no previous element */
    } else {
        /* get order of the next element */
        if ((err_info = srpds_load_next(ctx, mod_ns, prev, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* "no previous element and no next element" might
             * mean two things - either the max order was not
             * inserted yet or it was but all elements of the
             * list were deleted */

            /* set max order for lists and leaf-lists */
            if ((err_info = srpds_set_maxord(ctx, mod_ns, path_no_pred, SRPDS_DB_UO_ELEMS_GAP_SIZE))) {
                goto cleanup;
            }

            *order = SRPDS_DB_UO_ELEMS_GAP_SIZE;
        } else if (next_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev, predicate))) {
                goto cleanup;
            }

            *order = next_order;
        } else {
            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev, predicate))) {
                goto cleanup;
            }

            *order = (uint64_t)(next_order / 2);
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Delete a user-ordered element from a list or a leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] orig_prev_pred Predicate of a previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_prepare_delete_uo_op(redisContext *ctx, const char *mod_ns, const char *path_no_pred, const char *predicate,
        const char *orig_prev_pred)
{
    /* set new prev field of the next element */
    return srpds_change_next_element(ctx, mod_ns, path_no_pred, predicate, orig_prev_pred);
}

/**
 * @brief Create a userordered element in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to store.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @param[in] tree Whole data tree.
 * @param[out] max_order Maximum order of the userordered list/leaflist.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_uo_op(redisContext *ctx, sr_datastore_t ds, const char *mod_ns, const struct lyd_node *node,
        const char *path, const char *path_no_pred, const struct lyd_node *tree, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
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
    if ((err_info = srpds_prepare_create_uo_op(ctx, mod_ns, path_no_pred, srpds_get_predicate(path, path_no_pred),
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
        if ((err_info = srpds_list_uo(mod_ns, path, node->schema->name, module_name, keys, keys_length, order,
                path_no_pred, prev, (prev[0] == '\0') ? 1 : 0, path_modif, match ? match->meta : NULL, &argv))) {
            goto cleanup;
        }
        break;
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        if ((err_info = srpds_leaflist_uo(mod_ns, path, node->schema->name, module_name,
                (node->flags & LYD_DEFAULT), value, order, path_no_pred, prev, (prev[0] == '\0') ? 1 : 0,
                path_modif, match ? match->meta : NULL, &argv))) {
            goto cleanup;
        }
        break;
    }

    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ERR, NULL))) {
        goto cleanup;
    }

cleanup:
    free(path_modif);
    free(prev);
    free(keys);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Delete a userordered element from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to delete.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_op(redisContext *ctx, const char *mod_ns, const struct lyd_node *node, const char *path,
        const char *path_no_pred)
{
    sr_error_info_t *err_info = NULL;
    char *orig_prev = NULL;

    /* get orig_prev value */
    if ((err_info = srpds_get_orig_prev_value(plugin_name, node, &orig_prev))) {
        goto cleanup;
    }

    /* prepare deletion of an element from the user-ordered list */
    if ((err_info = srpds_prepare_delete_uo_op(ctx, mod_ns, path_no_pred, srpds_get_predicate(path, path_no_pred),
            orig_prev))) {
        goto cleanup;
    }

    /* delete the element */
    if ((err_info = srpds_query(ctx, CHCK_ERR, NULL, "DEL %s:data:%s", mod_ns, path))) {
        goto cleanup;
    }

cleanup:
    free(orig_prev);
    return err_info;
}

/**
 * @brief Move/update a userordered element in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] path_no_pred Path without a predicate.
 * @param[in] tree Whole data tree.
 * @param[out] max_order Maximum order of the userordered list/leaflist.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_uo_op(redisContext *ctx, sr_datastore_t ds, const char *mod_ns, const struct lyd_node *node,
        const char *path, const char *path_no_pred, const struct lyd_node *tree, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
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
    if ((err_info = srpds_prepare_delete_uo_op(ctx, mod_ns, path_no_pred, predicate, orig_prev))) {
        goto cleanup;
    }

    /* insert a new element into the user-ordered list */
    if ((err_info = srpds_prepare_create_uo_op(ctx, mod_ns, path_no_pred, predicate, prev, max_order, &order))) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }

    /* replace command */
    switch (node->schema->nodetype) {
    case LYS_LIST:
        /* add nothing */
        break;
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        srpds_argv_add(&argv, "e_dflt_flag", 11);
        if ((err_info = srpds_argv_add_format(&argv, "%d", node->flags & LYD_DEFAULT))) {
            goto cleanup;
        }
        srpds_argv_add(&argv, "g_value", 7);
        srpds_argv_add(&argv, value, strlen(value));
        break;
    }
    srpds_argv_add(&argv, "i_order", 7);
    if ((err_info = srpds_argv_add_format(&argv, "%" PRIu64, order))) {
        goto cleanup;
    }
    srpds_argv_add(&argv, "k_prev", 6);
    srpds_argv_add(&argv, prev, strlen(prev));
    srpds_argv_add(&argv, "l_is_prev_empty", 15);
    if ((err_info = srpds_argv_add_format(&argv, "%d", (prev[0] == '\0') ? 1 : 0))) {
        goto cleanup;
    }

    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata immediately (no bulking) */
        if ((err_info = srpds_delete_meta(ctx, mod_ns, path, NULL))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add new metadata */
        if ((err_info = srpds_add_meta(match->meta, &argv))) {
            goto cleanup;
        }
    }

    /* send query */
    if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ERR, NULL))) {
        goto cleanup;
    }

cleanup:
    free(prev);
    free(orig_prev);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Update node's default flag and metadata.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_none_op(redisContext *ctx, sr_datastore_t ds, const char *mod_ns, const struct lyd_node *node, const char *path,
        const struct lyd_node *tree, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
    struct lyd_node *match = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM) && (ds != SR_DS_OPERATIONAL)) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }

    /* update default flag */
    if (node->schema->nodetype & LYD_NODE_TERM) {
        srpds_argv_add(&argv, "e_dflt_flag", 11);
        if ((err_info = srpds_argv_add_format(&argv, "%d", node->flags & LYD_DEFAULT))) {
            goto cleanup;
        }
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata */
        if ((err_info = srpds_delete_meta(ctx, mod_ns, path, bulk))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add metadata */
        if ((err_info = srpds_add_meta(match->meta, &argv))) {
            goto cleanup;
        }
    }

    /* send query */
    if (bulk) {
        if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_query_argv(ctx, &argv, CHCK_ERR, NULL))) {
            goto cleanup;
        }
    }

cleanup:
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Create a standard node in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to store.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op(redisContext *ctx, sr_datastore_t ds, const char *mod_ns, const struct lyd_node *node,
        const char *path, const struct lyd_node *tree, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
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

    switch (node->schema->nodetype) {
    case LYS_CONTAINER:
        if ((err_info = srpds_container(mod_ns, path, node->schema->name, module_name, path_modif,
                match ? match->meta : NULL, &argv))) {
            goto cleanup;
        }
        break;
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
            goto cleanup;
        }
        if ((err_info = srpds_list(mod_ns, path, node->schema->name, module_name, keys, keys_length, path_modif,
                match ? match->meta : NULL, &argv))) {
            goto cleanup;
        }
        break;
    case LYS_LEAF:
    case LYS_LEAFLIST:
        value = lyd_get_value(node);
        if ((err_info = srpds_term(mod_ns, path, node->schema->name, module_name, (node->flags & LYD_DEFAULT),
                value, path_modif, match ? match->meta : NULL, &argv))) {
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
        if ((err_info = srpds_any(mod_ns, path, node->schema->name, module_name, any_value,
                (((struct lyd_node_any *)node)->value_type == LYD_ANYDATA_JSON), path_modif,
                match ? match->meta : NULL, &argv))) {
            goto cleanup;
        }
        break;
    default:
        break;
    }

    /* insert element */
    if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
        goto cleanup;
    }

cleanup:
    free(path_modif);
    free(any_value);
    free(keys);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Delete a standard node from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to the node.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_op(redisContext *ctx, const char *mod_ns, const char *path, redis_bulk_t *bulk)
{
    return srpds_bulk_query(ctx, bulk, "DEL %s:data:%s", mod_ns, path);
}

/**
 * @brief Update a standard node in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Node to update.
 * @param[in] path Path to the node.
 * @param[in] tree Whole data tree.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op(redisContext *ctx, sr_datastore_t ds, const char *mod_ns, const struct lyd_node *node,
        const char *path, const struct lyd_node *tree, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
    const char *value;
    char *any_value = NULL;
    struct lyd_node *match = NULL;

    /* get value */
    if ((err_info = srpds_get_norm_values(plugin_name, node, &value, &any_value))) {
        goto cleanup;
    }

    srpds_argv_add(&argv, "HSET", 4);
    if ((err_info = srpds_argv_add_format(&argv, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }

    /* update value */
    srpds_argv_add(&argv, "g_value", 7);
    srpds_argv_add(&argv, value, strlen(value));

    /* handle default flag update */
    if (node->schema->nodetype & LYD_NODE_TERM) {
        srpds_argv_add(&argv, "e_dflt_flag", 11);
        if ((err_info = srpds_argv_add_format(&argv, "%d", node->flags & LYD_DEFAULT))) {
            goto cleanup;
        }
    }

    /* metadata are only stored in oper ds */
    if (ds == SR_DS_OPERATIONAL) {
        /* delete metadata (with bulking) */
        if ((err_info = srpds_delete_meta(ctx, mod_ns, path, bulk))) {
            goto cleanup;
        }

        /* find the node in the mod_data to read metadata from */
        if ((err_info = srpds_find_node(plugin_name, node, tree, &match))) {
            goto cleanup;
        }

        /* add new metadata */
        if ((err_info = srpds_add_meta(match->meta, &argv))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
        goto cleanup;
    }

cleanup:
    free(any_value);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Load state data subtree (only for state data).
 *
 * @param[in] ctx Redis context.
 * @param[in] set Set of data nodes which need to be stored.
 * @param[in] node Data subtree.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_state_recursively(redisContext *ctx, const struct ly_set *set, const struct lyd_node *node,
        const char *mod_ns, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
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
        if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name,
                sibling->parent->schema->module->name)) {
            module_name = sibling->schema->module->name;
        } else {
            module_name = NULL;
        }

        switch (sibling->schema->nodetype) {
        case LYS_CONTAINER:
            if ((err_info = srpds_container(mod_ns, path, sibling->schema->name, module_name, path_modif,
                    sibling->meta, &argv))) {
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

            if ((err_info = srpds_list_uo(mod_ns, path, sibling->schema->name, module_name, keys, keys_length, order,
                    path_no_pred, NULL, 0, path_modif, sibling->meta, &argv))) {
                goto cleanup;
            }
            order++;
            break;
        case LYS_LEAF:
            value = lyd_get_value(sibling);
            if ((srpds_term(mod_ns, path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT, value,
                    path_modif, sibling->meta, &argv))) {
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
            if ((err_info = srpds_leaflist_uo(mod_ns, path, sibling->schema->name, module_name,
                    sibling->flags & LYD_DEFAULT, value, order, path_no_pred, NULL, 0, path_modif, sibling->meta,
                    &argv))) {
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
            if ((err_info = srpds_any(mod_ns, path, sibling->schema->name, module_name, value,
                    (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON), path_modif,
                    sibling->meta, &argv))) {
                goto cleanup;
            }
            break;
        default:
            break;
        }

        /* create a new node */
        if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
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
        free(keys);
        keys = NULL;
        keys_length = 0;
        srpds_argv_destroy(&argv);

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_state_recursively(ctx, NULL, child, mod_ns, bulk))) {
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
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Load data matching the regexes from the database and delete them, store this operation inside bulk.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @param[in] regex1 First regex.
 * @param[in] regex2 Second regex.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_del_regex(redisContext *ctx, const char *mod_ns, redis_bulk_t *bulk, const char *regex1,
        const char *regex2)
{
    sr_error_info_t *err_info = NULL;
    const char *script =
            "local reply = redis.pcall('FT.AGGREGATE', KEYS[1], '*', 'LOAD', '1', '__key', 'LIMIT', '0', '"
            REDIS_MAX_AGGREGATE_LIMIT "', 'WITHCURSOR', 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "local numkeys = #KEYS; "
            "while 1 do "
            "local n = table.getn(reply[1]); "
            "for i=2,n do "
            "local reply2; "
            "for j=2,numkeys do "
            "if string.find(reply[1][i][2], KEYS[j]) then "
            "reply2 = redis.pcall('DEL', reply[1][i][2]); "
            "if reply2 ~= 1 then "
            "return reply2['err']; "
            "end "
            "end "
            "end "
            "end "
            "if reply[2] == 0 then break end "
            "reply = redis.pcall('FT.CURSOR', 'READ', KEYS[1], reply[2], 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "end "
            "return 0; ";

    if ((err_info = srpds_bulk_query(ctx, bulk, "EVAL %s %d %s:data %s %s", script, 3, mod_ns, regex1, regex2))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Delete a whole subtree of data from the database (including this @p path).
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to the top node of the subtree.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_delete_subtree(redisContext *ctx, const char *mod_ns, const char *path, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    char *dbkey = NULL, *escaped = NULL, *regex1 = NULL, *regex2 = NULL;

    /* get database key */
    if (asprintf(&dbkey, "%s:data:%s", mod_ns, path) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    if ((err_info = srpds_escape_string(plugin_name, dbkey, '%', &escaped))) {
        goto cleanup;
    }

    if (asprintf(&regex1, "^%s%%/", escaped) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    if (asprintf(&regex2, "^%s%%[", escaped) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    /* delete the whole subtree */
    if ((err_info = srpds_load_and_del_regex(ctx, mod_ns, bulk, regex1, regex2))) {
        goto cleanup;
    }

cleanup:
    free(dbkey);
    free(escaped);
    free(regex1);
    free(regex2);
    return err_info;
}

/**
 * @brief Store the whole subtree using @p sibling inside a helper structure with info from mod_data.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Subtree from diff to use.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_tree2store(redisContext *ctx, const struct lyd_node *mod_data, const struct lyd_node *node,
        const char *mod_ns, redis_bulk_t *bulk)
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
        if ((err_info = srpds_bulk_query(ctx, bulk, "DEL %s:data:%s", mod_ns, path_no_pred))) {
            goto cleanup;
        }
    }
    if ((err_info = srpds_bulk_delete_subtree(ctx, mod_ns, path_no_pred, bulk))) {
        goto cleanup;
    }

    /* we NEED to store a deleted subtree (could be a list or a leaf-list instance with siblings which we just
     * deleted) */
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
                if ((err_info = srpds_store_state_recursively(ctx, set, set->dnodes[0], mod_ns, bulk))) {
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

static sr_error_info_t *srpds_store_diff_recursively(redisContext *ctx, sr_datastore_t ds,
        const struct lyd_node *mod_data, const struct lyd_node *node, const char *mod_ns, char parent_op,
        redis_bulk_t *bulk);

/**
 * @brief Store the node @p sibling inside a helper structure with info from diff.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Whole module data tree.
 * @param[in] sibling Current data node in the diff.
 * @param[in] this_op Operation on this node.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_use_diff2store(redisContext *ctx, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *sibling, char this_op, const char *mod_ns, redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *child = NULL;
    char *path = NULL;

    /* userordered lists and leaf-lists are stored elsewhere */
    if (!lysc_is_userordered(sibling->schema)) {
        /* get path */
        path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
        if (!path) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
            return err_info;
        }

        /* operation */
        switch (this_op) {
        case 'n':
            if ((err_info = srpds_none_op(ctx, ds, mod_ns, sibling, path, mod_data, bulk))) {
                goto cleanup;
            }
            break;
        case 'c':
            if ((err_info = srpds_create_op(ctx, ds, mod_ns, sibling, path, mod_data, bulk))) {
                goto cleanup;
            }
            break;
        case 'd':
            if ((err_info = srpds_delete_op(ctx, mod_ns, path, bulk))) {
                goto cleanup;
            }
            break;
        case 'r':
            if ((err_info = srpds_replace_op(ctx, ds, mod_ns, sibling, path, mod_data, bulk))) {
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
    }

    if ((child = lyd_child_no_keys(sibling))) {
        if ((err_info = srpds_store_diff_recursively(ctx, ds, mod_data, child, mod_ns, this_op, bulk))) {
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
 * @param[in] ctx Redis context.
 * @param[in] node Opaque node.
 * @param[in] op Operation to perform.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_handle_opaque_node(redisContext *ctx, const struct lyd_node *node, char op, const char *mod_ns,
        redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node_opaq *opaque = NULL;
    char *path = NULL, *path_modif = NULL;
    const char *module_name = NULL, *value = NULL;
    redis_argv_t argv = {0};
    struct lyd_attr *attr = NULL;

    /* get node's path */
    path = lyd_path(node, LYD_PATH_STD, NULL, 0);
    if (!path) {
        ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
        goto cleanup;
    }

    /* get value */
    value = lyd_get_value(node);

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
        if ((err_info = srpds_bulk_query(ctx, bulk, "DEL %s:data:%s$%s", mod_ns, path, value))) {
            goto cleanup;
        }
        break;
    case 'c':
        /* get modified version of path */
        if ((err_info = srpds_get_modif_path(plugin_name, path, &path_modif))) {
            goto cleanup;
        }

        /* get module name */
        module_name = opaque->name.module_name;

        /* create new opaque node */
        if ((err_info = srpds_opaque(mod_ns, path, opaque->name.name, module_name, value, path_modif, &argv))) {
            goto cleanup;
        }

        if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
            goto cleanup;
        }
        break;
    default:
        ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
        goto cleanup;
    }

cleanup:
    free(path);
    free(path_modif);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Load the whole diff and store the data in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Current data node in the diff.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] parent_op Operation on the node's parent.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_diff_recursively(redisContext *ctx, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *node, const char *mod_ns, char parent_op, redis_bulk_t *bulk)
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
            if ((err_info = srpds_handle_opaque_node(ctx, sibling, 0, mod_ns, bulk))) {
                goto cleanup;
            }
        } else if (!(sibling->schema->flags & LYS_CONFIG_W)) {
            /* only delete and store a state subtree if it was not stored before */
            if (previous_schema != sibling->schema) {
                if ((err_info = srpds_use_tree2store(ctx, mod_data, sibling, mod_ns, bulk))) {
                    goto cleanup;
                }
            }
            previous_schema = sibling->schema;
        } else {
            if ((err_info = srpds_use_diff2store(ctx, ds, mod_data, sibling, this_op, mod_ns, bulk))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load the whole diff and store the userordered data in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] node Current data node in the diff.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] parent_op Operation on the node's parent.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_diff_uo_recursively(redisContext *ctx, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *node, const char *mod_ns, char parent_op)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = node;
    struct lyd_node *child = NULL;
    struct lyd_meta *meta_op;
    char this_op = 0;
    char *path = NULL, *path_no_pred = NULL;
    uint64_t max_order = 0;

    while (sibling) {
        /* n - none, c - create, d - delete, r - replace */
        meta_op = lyd_find_meta(sibling->meta, NULL, "yang:operation");
        if (meta_op) {
            this_op = lyd_get_meta_value(meta_op)[0];
        } else {
            this_op = parent_op;
        }

        /* node is a userordered list or leaf-list and is not a state node */
        if (lysc_is_userordered(sibling->schema) && (sibling->schema->flags & LYS_CONFIG_W)) {
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
                if ((err_info = srpds_none_op(ctx, ds, mod_ns, sibling, path, mod_data, NULL))) {
                    goto cleanup;
                }
                break;
            case 'c':
                if ((err_info = srpds_create_uo_op(ctx, ds, mod_ns, sibling, path, path_no_pred, mod_data,
                        &max_order))) {
                    goto cleanup;
                }
                break;
            case 'd':
                if ((err_info = srpds_delete_uo_op(ctx, mod_ns, sibling, path, path_no_pred))) {
                    goto cleanup;
                }
                break;
            case 'r':
                if ((err_info = srpds_replace_uo_op(ctx, ds, mod_ns, sibling, path, path_no_pred, mod_data,
                        &max_order))) {
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
                if ((err_info = srpds_set_maxord(ctx, mod_ns, path_no_pred, max_order))) {
                    goto cleanup;
                }
                max_order = 0;
            }

            /* free memory early before further recursion */
            free(path);
            path = NULL;
            free(path_no_pred);
            path_no_pred = NULL;
        }

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_diff_uo_recursively(ctx, ds, mod_data, child, mod_ns, this_op))) {
                goto cleanup;
            }
        }
        sibling = sibling->next;
    }

cleanup:
    free(path);
    free(path_no_pred);
    return err_info;
}

/**
 * @brief Store the whole diff inside the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Datastore in use.
 * @param[in] mod_data Module data tree to store.
 * @param[in] mod_diff Module diff.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *
srpds_store_diff(redisContext *ctx, sr_datastore_t ds, const struct lyd_node *mod_data,
        const struct lyd_node *mod_diff, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    /* first userordered data are stored without bulking (because of mod_diff's nature) */
    if ((err_info = srpds_store_diff_uo_recursively(ctx, ds, mod_data, mod_diff, mod_ns, 0))) {
        goto cleanup;
    }

    /* second all other data are stored (including opaque, state and configuration) */
    if ((err_info = srpds_store_diff_recursively(ctx, ds, mod_data, mod_diff, mod_ns, 0, &bulk))) {
        goto cleanup;
    }

    /* check replies from the pipeline */
    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load the whole data tree and store the data in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_data Whole data tree.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_data_recursively(redisContext *ctx, const struct lyd_node *mod_data, const char *mod_ns,
        redis_bulk_t *bulk)
{
    sr_error_info_t *err_info = NULL;
    redis_argv_t argv = {0};
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
            if ((err_info = srpds_handle_opaque_node(ctx, sibling, 'c', mod_ns, bulk))) {
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
        if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name,
                sibling->parent->schema->module->name)) {
            module_name = sibling->schema->module->name;
        } else {
            module_name = NULL;
        }

        /* create all data */
        switch (sibling->schema->nodetype) {
        case LYS_CONTAINER:
            if ((err_info = srpds_container(mod_ns, path, sibling->schema->name, module_name, path_modif,
                    sibling->meta, &argv))) {
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

                if ((err_info = srpds_list_uo(mod_ns, path, sibling->schema->name, module_name, keys, keys_length,
                        state_order, path_no_pred, NULL, 0, path_modif, sibling->meta, &argv))) {
                    goto cleanup;
                }
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered lists */
                if ((err_info = srpds_list_uo(mod_ns, path, sibling->schema->name, module_name, keys, keys_length,
                        uo_order, path_no_pred, prev, (prev[0] == '\0') ? 1 : 0, path_modif, sibling->meta,
                        &argv))) {
                    goto cleanup;
                }
                uo_order += 1024;
            } else {
                /* lists */
                if ((err_info = srpds_list(mod_ns, path, sibling->schema->name, module_name, keys, keys_length,
                        path_modif, sibling->meta, &argv))) {
                    goto cleanup;
                }
            }
            break;
        case LYS_LEAF:
            value = lyd_get_value(sibling);
            if ((srpds_term(mod_ns, path, sibling->schema->name, module_name, sibling->flags & LYD_DEFAULT,
                    value, path_modif, sibling->meta, &argv))) {
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

                if ((err_info = srpds_leaflist_uo(mod_ns, path, sibling->schema->name, module_name,
                        sibling->flags & LYD_DEFAULT, value, state_order, path_no_pred, NULL, 0, path_modif,
                        sibling->meta, &argv))) {
                    goto cleanup;
                }
                ++state_order;
            } else if (lysc_is_userordered(sibling->schema)) {
                /* userordered leaf-lists */
                if ((err_info = srpds_leaflist_uo(mod_ns, path, sibling->schema->name, module_name,
                        sibling->flags & LYD_DEFAULT, value, uo_order, path_no_pred, prev,
                        (prev[0] == '\0') ? 1 : 0, path_modif, sibling->meta, &argv))) {
                    goto cleanup;
                }
                uo_order += 1024;
            } else {
                /* leaf-lists */
                if ((err_info = srpds_term(mod_ns, path, sibling->schema->name, module_name,
                        sibling->flags & LYD_DEFAULT, value, path_modif, sibling->meta, &argv))) {
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
            if ((err_info = srpds_any(mod_ns, path, sibling->schema->name, module_name, value,
                    (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON), path_modif, sibling->meta,
                    &argv))) {
                goto cleanup;
            }
            break;
        }

        if ((err_info = srpds_bulk_query_argv(ctx, &argv, bulk))) {
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
        free(any_value);
        any_value = NULL;
        free(prev);
        prev = NULL;
        free(keys);
        keys = NULL;
        keys_length = 0;
        srpds_argv_destroy(&argv);

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_data_recursively(ctx, child, mod_ns, bulk))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;
    }

cleanup:
    free(path);
    free(path_no_pred);
    free(path_modif);
    free(any_value);
    free(prev);
    free(keys);
    srpds_argv_destroy(&argv);
    return err_info;
}

/**
 * @brief Load data from the database and delete them.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] index_type Type of the data to retrieve (meta or data).
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_del(redisContext *ctx, const char *mod_ns, const char *index_type, redis_bulk_t *bulk)
{
    return srpds_bulk_query(ctx, bulk, "EVAL %s 1 %s:%s",
            "local reply = redis.pcall('FT.AGGREGATE', KEYS[1], '*', 'LOAD', '1', '__key', 'LIMIT', '0', '"
            REDIS_MAX_AGGREGATE_LIMIT "', 'WITHCURSOR', 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "while 1 do "
            "local n = table.getn(reply[1]); "
            "local reply2; "
            "for i=2,n do "
            "reply2 = redis.pcall('DEL', reply[1][i][2]); "
            "if reply2 ~= 1 then "
            "return reply2['err']; "
            "end "
            "end "
            "if reply[2] == 0 then break end "
            "reply = redis.pcall('FT.CURSOR', 'READ', KEYS[1], reply[2], 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "end "
            "return 0; ",
            mod_ns, index_type);
}

/**
 * @brief Load data (only :data and :meta) from the database and delete them.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_del_data(redisContext *ctx, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    if ((err_info = srpds_load_and_del(ctx, mod_ns, "meta", &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_and_del(ctx, mod_ns, "data", &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load data from the database and copy them to another database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] index_type Type of the data to retrieve (meta or data).
 * @param[in] trg_ds Target datastore.
 * @param[out] bulk Bulk to use.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_copy(redisContext *ctx, const char *mod_ns, const char *index_type, const char *trg_ds,
        redis_bulk_t *bulk)
{
    return srpds_bulk_query(ctx, bulk, "EVAL %s 1 %s:%s %s",
            "local reply = redis.pcall('FT.AGGREGATE', KEYS[1], '*', 'LOAD', '1', '__key', 'LIMIT', '0', '"
            REDIS_MAX_AGGREGATE_LIMIT "', 'WITHCURSOR', 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "while 1 do "
            "local n = table.getn(reply[1]); "
            "local reply2; "
            "for i=2,n do "
            "local index; "
            "index = string.find(reply[1][i][2],':',0); "
            "index = string.find(reply[1][i][2],':',index+1); "
            "reply2 = redis.pcall('COPY', reply[1][i][2], ARGV[1] .. string.sub(reply[1][i][2], index), 'REPLACE'); "
            "if reply2 ~= 1 then "
            "return reply2['err']; "
            "end "
            "end "
            "if reply[2] == 0 then break end "
            "reply = redis.pcall('FT.CURSOR', 'READ', KEYS[1], reply[2], 'COUNT', '" REDIS_MAX_AGGREGATE_COUNT "'); "
            "if reply['err'] ~= nil then "
            "return reply['err']; "
            "end "
            "end "
            "return 0; ",
            mod_ns, index_type, trg_ds);
}

/**
 * @brief Load data (only :data and :meta) from the database and copy them to the target datastore.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns_src Database prefix for the module of the source datastore.
 * @param[in] trg_ds Target datastore.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_copy_data(redisContext *ctx, const char *mod_ns_src, const char *trg_ds)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    if ((err_info = srpds_load_and_copy(ctx, mod_ns_src, "meta", trg_ds, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_and_copy(ctx, mod_ns_src, "data", trg_ds, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Store the whole data tree in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_data Whole data tree.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *
srpds_store_data(redisContext *ctx, const struct lyd_node *mod_data, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    /* delete all data */
    if ((err_info = srpds_load_and_del_data(ctx, mod_ns))) {
        goto cleanup;
    }

    /* store all data */
    if ((err_info = srpds_store_data_recursively(ctx, mod_data, mod_ns, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Create or update global flags (last-modif and candidate-modified).
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] ds Given datastore.
 * @param[in] spec Time of the last modification.
 * @param[in] candidate_modified Whether candidate datastore is modified.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_set_flags(redisContext *ctx, const char *mod_ns, sr_datastore_t ds, struct timespec *spec,
        int candidate_modified)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    /* set last-modified flag in seconds */
    if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:glob:last-modified-sec %" PRId64, mod_ns, spec->tv_sec))) {
        goto cleanup;
    }

    /* set last-modified flag in nanoseconds */
    if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:glob:last-modified-nsec %" PRId64, mod_ns, spec->tv_nsec))) {
        goto cleanup;
    }

    /* set candidate-modified flag */
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:glob:candidate-modified %d", mod_ns,
                candidate_modified))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Delete module global and permission flags from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Given datastore.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_glob_and_perm(redisContext *ctx, sr_datastore_t ds, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:glob:last-modified-sec", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:glob:last-modified-nsec", mod_ns))) {
        goto cleanup;
    }
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:glob:candidate-modified", mod_ns))) {
            goto cleanup;
        }
    }
    if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:perm:owner", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:perm:group", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_query(ctx, &bulk, "DEL %s:perm:perm", mod_ns))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Create all necessary indices.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_indices(redisContext *ctx, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    /* index for data */
    if ((err_info = srpds_bulk_query(ctx, &bulk,
            "FT.CREATE %s:data "
            "ON HASH PREFIX 1 %s:data: "
            "STOPWORDS 0 "
            "SCHEMA a_path TAG CASESENSITIVE "
            "b_name TAG CASESENSITIVE "
            "c_type NUMERIC "
            "d_module_name TAG CASESENSITIVE "
            "e_dflt_flag NUMERIC "
            "f_keys TAG CASESENSITIVE "
            "g_value TAG CASESENSITIVE "
            "h_valtype NUMERIC "
            "i_order NUMERIC "
            "j_path_no_pred TAG CASESENSITIVE "
            "k_prev TAG CASESENSITIVE "
            "l_is_prev_empty NUMERIC "
            "m_path_modif TAG CASESENSITIVE "
            "n_meta_count NUMERIC ", mod_ns, mod_ns))) {
        goto cleanup;
    }

    /* index for maxorder */
    if ((err_info = srpds_bulk_query(ctx, &bulk,
            "FT.CREATE %s:meta "
            "ON HASH PREFIX 1 %s:meta: "
            "STOPWORDS 0 "
            "SCHEMA value NUMERIC", mod_ns, mod_ns))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Destroy all created indices.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_destroy_indices(redisContext *ctx, char *mod_ns)
{
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    /* it is possible to include option DD at the end to delete all associated data as well */
    if ((err_info = srpds_bulk_query(ctx, &bulk, "FT.DROPINDEX %s:data DD", mod_ns))) {
        goto cleanup;
    }

    /* index for maxorder */
    if ((err_info = srpds_bulk_query(ctx, &bulk, "FT.DROPINDEX %s:meta DD", mod_ns))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_candidate_modified(const struct lys_module *mod, void *plg_data, int *modified)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    assert(mod && modified);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(SR_DS_CANDIDATE, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* get candidate-modified flag */
    if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:glob:candidate-modified", mod_ns))) {
        goto cleanup;
    }
    *modified = atoi(reply->str);

cleanup:
    free(mod_ns);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_copy(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns_src = NULL, *mod_ns_trg = NULL;
    sr_error_info_t *err_info = NULL;
    struct timespec spec = {0};

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    /* get module namespace (+ module name) for source datastore */
    if ((err_info = srpds_get_mod_ns(src_ds, mod->name, 0, 0, &mod_ns_src))) {
        goto cleanup;
    }

    /* get module namespace (+ module name) for target datastore */
    if ((err_info = srpds_get_mod_ns(trg_ds, mod->name, 0, 0, &mod_ns_trg))) {
        goto cleanup;
    }

    /* the contents of the target datastore should first be removed */
    if ((err_info = srpds_load_and_del_data(ctx, mod_ns_trg))) {
        goto cleanup;
    }

    /* load data from the source datastore and copy it to the target datastore */
    if ((err_info = srpds_load_and_copy_data(ctx, mod_ns_src, srpds_ds2dsprefix(trg_ds)))) {
        goto cleanup;
    }

    clock_gettime(CLOCK_REALTIME, &spec);

    /* set flags - e.g. last-modified and candidate-modified */
    if ((err_info = srpds_set_flags(ctx, mod_ns_trg, trg_ds, &spec, 1))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns_src);
    free(mod_ns_trg);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_store_prepare(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid,
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
srpds_redis_store_commit(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid,
        const struct lyd_node *mod_diff, const struct lyd_node *mod_data, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    redisReply *reply = NULL;
    sr_error_info_t *err_info = NULL;
    char *mod_ns = NULL;
    int modified = 1;
    struct timespec spec = {0};

    assert(mod);

    /* for candidate ds learn if modified */
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_redis_candidate_modified(mod, plg_data, &modified))) {
            return err_info;
        }
    }

    /* if not modified, then copy running */
    if (!modified) {
        if ((err_info = srpds_redis_copy(mod, SR_DS_CANDIDATE, SR_DS_RUNNING, plg_data))) {
            return err_info;
        }
    }

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, cid, sid, &mod_ns))) {
        goto cleanup;
    }

    if (ds == SR_DS_OPERATIONAL) {
        /* new connection id and session id can create a new separate collection of data,
         * new index should be created */
        if ((err_info = srpds_query(ctx, 0, &reply, "FT.INFO %s:data", mod_ns))) {
            goto cleanup;
        }

        /* if index does not exist and data is not empty, we need to create an index */
        if ((reply->type == REDIS_REPLY_ERROR) && mod_data) {
            if ((err_info = srpds_create_indices(ctx, mod_ns))) {
                goto cleanup;
            }
        }
    }

    /* in case of empty mod_data, just delete everything (do not bother storing) */
    if (!mod_data) {
        if (ds == SR_DS_OPERATIONAL) {
            /* if index exists and empty data is passed, destroy index and delete data (probably ending session) */
            if (reply->type != REDIS_REPLY_ERROR) {
                if ((err_info = srpds_destroy_indices(ctx, mod_ns))) {
                    goto cleanup;
                }
            }
        } else {
            /* delete all data */
            if ((err_info = srpds_load_and_del_data(ctx, mod_ns))) {
                goto cleanup;
            }
        }
    } else if (mod_diff) {
        if ((err_info = srpds_store_diff(ctx, ds, mod_data, mod_diff, mod_ns))) {
            goto cleanup;
        }
    } else {
        /* diff is not always present, in that case store all data */
        if ((err_info = srpds_store_data(ctx, mod_data, mod_ns))) {
            goto cleanup;
        }
    }

    /* for last-modif flag, use data collection without cid and sid */
    if (ds == SR_DS_OPERATIONAL) {
        free(mod_ns);
        mod_ns = NULL;
        if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
            goto cleanup;
        }
    }

    clock_gettime(CLOCK_REALTIME, &spec);

    /* set flags, e.g. last-modified and/or candidate-modified */
    if ((err_info = srpds_set_flags(ctx, mod_ns, ds, &spec, 1))) {
        goto cleanup;
    }

cleanup:
    freeReplyObject(reply);
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_access_get(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, char **owner, char **group, mode_t *perm)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    sr_error_info_t *err_info = NULL;
    char *mod_ns = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_access(ctx, mod_ns, owner, group, perm))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    redis_bulk_t bulk = {0};

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* set the owner */
    /* WARNING!!! Usernames should conform to this regex '^[a-z][_-a-z0-9]*\$',
     * other usernames could cause malfunction of the whole plugin */
    if (owner) {
        if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:perm:owner %s", mod_ns, owner))) {
            goto cleanup;
        }
    }

    /* set the group */
    if (group) {
        if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:perm:group %s", mod_ns, group))) {
            goto cleanup;
        }
    }

    /* set the permissions */
    if (perm) {
        if ((err_info = srpds_bulk_query(ctx, &bulk, "SET %s:perm:perm %u", mod_ns, perm))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_access_check(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, int *read, int *write)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    sr_error_info_t *err_info = NULL;
    int is_owner = 0, in_group = 0;
    char *username = NULL, *groupname = NULL,
            *owner = NULL, *group = NULL, *mod_ns = NULL;
    mode_t perm = 0;

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* learn module access */
    if ((err_info = srpds_get_access(ctx, mod_ns, &owner, &group, &perm))) {
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
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_init(const struct lys_module *mod, sr_datastore_t ds, void *plg_data)
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
srpds_redis_install(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    char *username = NULL, *groupname = NULL;
    struct timespec spec = {0};

    assert(mod && perm);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* if no owner provided use current process user */
    if (!owner && (err_info = srpds_uid2usr(plugin_name, getuid(), &username))) {
        goto cleanup;
    }

    /* if no group provided use current process group */
    if (!group && (err_info = srpds_gid2grp(plugin_name, getgid(), &groupname))) {
        goto cleanup;
    }

    /* set access data + data init */
    if ((err_info = srpds_redis_access_set(mod, ds, owner ? owner : username, group ? group : groupname, perm,
            plg_data))) {
        goto cleanup;
    }

    /* create indices for loading - sr_<datastore>:<shm_prefix>:<module>:data and
     * sr_operational:<shm_prefix>:<module>:meta - see load */
    if ((err_info = srpds_create_indices(ctx, mod_ns))) {
        goto cleanup;
    }

    if ((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        /* set flags, e.g. last-modified and/or candidate-modified */
        clock_gettime(CLOCK_REALTIME, &spec);
        if ((err_info = srpds_set_flags(ctx, mod_ns, ds, &spec, 0))) {
            goto cleanup;
        }
    } else {
        /* set flags, e.g. last-modified and/or candidate-modified */
        if ((err_info = srpds_set_flags(ctx, mod_ns, ds, &spec, 0))) {
            goto cleanup;
        }
    }

cleanup:
    free(mod_ns);
    free(username);
    free(groupname);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_uninstall(const struct lys_module *mod, sr_datastore_t ds, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* destroy indices and data */
    if ((err_info = srpds_destroy_indices(ctx, mod_ns))) {
        goto cleanup;
    }

    /* delete all global metadata and permissions (access rights, flags) */
    if ((err_info = srpds_delete_glob_and_perm(ctx, ds, mod_ns))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_load(const struct lys_module *mod, sr_datastore_t ds, sr_cid_t cid, uint32_t sid, const char **xpaths,
        uint32_t xpath_count, void *plg_data, struct lyd_node **mod_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    redisReply *reply = NULL;
    char *mod_ns = NULL, *xpath_filter = NULL;
    sr_error_info_t *err_info = NULL;

    assert(mod && mod_data);

    *mod_data = NULL;

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, cid, sid, &mod_ns))) {
        goto cleanup;
    }

    /* new connection id and session id can create a new separate collection of data,
     * new index should be created */
    if (ds == SR_DS_OPERATIONAL) {
        if ((err_info = srpds_query(ctx, 0, &reply, "FT.INFO %s:data", mod_ns))) {
            goto cleanup;
        }
        if (reply->type == REDIS_REPLY_ERROR) {
            if ((err_info = srpds_create_indices(ctx, mod_ns))) {
                goto cleanup;
            }
        }
    }

    if ((err_info = srpds_process_load_paths(mod->ctx, xpaths, xpath_count, (ds == SR_DS_OPERATIONAL),
            &xpath_filter))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_all(ctx, mod, ds, mod_ns, xpath_filter, mod_data))) {
        goto cleanup;
    }

cleanup:
    free(xpath_filter);
    free(mod_ns);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_last_modif(const struct lys_module *mod, sr_datastore_t ds, void *plg_data, struct timespec *mtime)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    assert(mod && mtime);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* get last-modified flag - seconds */
    if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:glob:last-modified-sec", mod_ns))) {
        goto cleanup;
    }
    mtime->tv_sec = strtoll(reply->str, NULL, 0);
    freeReplyObject(reply);
    reply = NULL;

    /* get last-modified flag - nanoseconds */
    if ((err_info = srpds_query(ctx, CHCK_ERR, &reply, "GET %s:glob:last-modified-nsec", mod_ns))) {
        goto cleanup;
    }
    mtime->tv_nsec = strtoll(reply->str, NULL, 0);

cleanup:
    free(mod_ns);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_candidate_reset(const struct lys_module *mod, void *plg_data)
{
    redis_plg_conn_data_t *pdata = (redis_plg_conn_data_t *)plg_data;
    redisContext *ctx = NULL;
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    struct timespec spec = {0};

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(SR_DS_CANDIDATE, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* reset the datastore */
    if ((err_info = srpds_load_and_del_data(ctx, mod_ns))) {
        goto cleanup;
    }

    /* set flags - e.g. last-modified and candidate-modified */
    if ((err_info = srpds_set_flags(ctx, mod_ns, SR_DS_CANDIDATE, &spec, 0))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    return err_info;
}

/**
 * @brief Comment for this function can be found in "plugins_datastore.h".
 *
 */
sr_error_info_t *
srpds_redis_conn_init(sr_conn_ctx_t *conn, void **plg_data)
{
    sr_error_info_t *err_info = NULL;
    redis_plg_conn_data_t *data;

    (void) conn;

    data = calloc(1, sizeof *data);
    if (!data) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    if (pthread_rwlock_init(&data->lock, NULL)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "pthread_rwlock_init()", "");
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
srpds_redis_conn_destroy(sr_conn_ctx_t *conn, void *plg_data)
{
    uint32_t i;
    redis_plg_conn_data_t *data = (redis_plg_conn_data_t *)plg_data;

    (void) conn;

    /* destroy all redis contexts in conn_pool */
    for (i = 0; i < data->size; ++i) {
        redisFree(data->conn_pool[i].ctx);
    }
    free(data->conn_pool);
    pthread_rwlock_destroy(&data->lock);
    free(data);
}

const struct srplg_ds_s srpds_redis = {
    .name = plugin_name,
    .install_cb = srpds_redis_install,
    .uninstall_cb = srpds_redis_uninstall,
    .init_cb = srpds_redis_init,
    .conn_init_cb = srpds_redis_conn_init,
    .conn_destroy_cb = srpds_redis_conn_destroy,
    .store_prepare_cb = srpds_redis_store_prepare,
    .store_commit_cb = srpds_redis_store_commit,
    .load_cb = srpds_redis_load,
    .copy_cb = srpds_redis_copy,
    .candidate_modified_cb = srpds_redis_candidate_modified,
    .candidate_reset_cb = srpds_redis_candidate_reset,
    .access_set_cb = srpds_redis_access_set,
    .access_get_cb = srpds_redis_access_get,
    .access_check_cb = srpds_redis_access_check,
    .last_modif_cb = srpds_redis_last_modif,
    .data_version_cb = NULL,
};
