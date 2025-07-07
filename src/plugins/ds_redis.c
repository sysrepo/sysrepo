/**
 * @file ds_redis.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief internal RedisDB datastore plugin
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

/* context should be different for each thread */
typedef struct redis_thread_data_s {
    redisContext *ctx;
    pthread_t id;
} redis_thread_data_t;

/* pool of connections */
typedef struct redis_plg_conn_data_s {
    pthread_rwlock_t lock;
    redis_thread_data_t *conn_pool;
    uint32_t size;
} redis_plg_conn_data_t;

/* command's arguments in a bulk operation */
struct redis_bulk_inner {
    int argnum; /* number of arguments */
    char **argv; /* array of arguments */
    int *allocd; /* array of booleans indicating which arguments are dynamically allocated */
    size_t *argvlen; /* array of argument's lengths */
    uint32_t idx; /* indicates how many arguments have already been added */
};

/* commands of a bulk operation */
struct redis_bulk {
    struct redis_bulk_inner *data; /* array of commands containing the command's arguments. */
    uint32_t size; /* size of the bulk */
    uint32_t idx; /* indicates how many commands have already been added */
};

/**
 * @brief Allocate and initialize resources for command's arguments.
 *
 * @param[in] argnum Number of command's arguments.
 * @param[out] data Structure containing the command's arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_docs_init(int argnum, struct redis_bulk_inner *data)
{
    sr_error_info_t *err_info = NULL;

    data->argv = (char **)calloc(argnum, sizeof *(data->argv));
    if (!(data->argv)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    data->allocd = (int *)calloc(argnum, sizeof *(data->allocd));
    if (!(data->allocd)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    data->argvlen = (size_t *)calloc(argnum, sizeof *(data->argvlen));
    if (!(data->argvlen)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    data->argnum = argnum;
    data->idx = 0;

cleanup:
    return err_info;
}

/**
 * @brief Add an argument that does not require dynamic allocation.
 *
 * @param[in] argv Argument to add.
 * @param[in] argvlen Argument's length.
 * @param[out] data Structure containing the command's arguments.
 */
static void
srpds_docs_add_const(const char *argv, size_t argvlen, struct redis_bulk_inner *data)
{
    data->argv[data->idx] = (char *)argv;
    data->allocd[data->idx] = 0;
    data->argvlen[data->idx] = argvlen;
    ++(data->idx);
}

/**
 * @brief Add an argument that requires dynamic allocation.
 *
 * @param[in] argv Argument to add.
 * @param[in] argvlen Argument's length.
 * @param[out] data Structure containing the command's arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_docs_add_alloc(const char *argv, size_t argvlen, struct redis_bulk_inner *data)
{
    sr_error_info_t *err_info = NULL;
    char *newstr = malloc(argvlen);

    if (!newstr) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "malloc()", "");
        goto cleanup;
    }
    memcpy(newstr, argv, argvlen);

    data->argv[data->idx] = newstr;
    data->allocd[data->idx] = 1;
    data->argvlen[data->idx] = argvlen;
    ++(data->idx);

cleanup:
    return err_info;
}

/**
 * @brief Add an argument in form of an input for vasprintf function.
 *
 * @param[in] format Format string (input for vasprintf function).
 * @param[in] args Arguments (input for vasprintf function).
 * @param[out] data Structure containing the command's arguments.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_docs_add_format(const char *format, va_list args, struct redis_bulk_inner *data)
{
    sr_error_info_t *err_info = NULL;
    char *newstr = NULL;

    if (vasprintf(&newstr, format, args) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }

    data->argv[data->idx] = newstr;
    data->allocd[data->idx] = 1;
    data->argvlen[data->idx] = strlen(newstr);
    ++(data->idx);

cleanup:
    return err_info;
}

/**
 * @brief Deallocate command's arguments.
 *
 * @param[out] data Structure containing the command's arguments.
 */
static void
srpds_docs_destroy(struct redis_bulk_inner *data)
{
    uint32_t i;

    for (i = 0; i < data->idx; ++i) {
        if (data->allocd[i]) {
            free(data->argv[i]);
        }
    }
    free(data->argv);
    free(data->allocd);
    free(data->argvlen);
}

/**
 * @brief Initialize the bulk containing commands for bulk operation.
 *
 * @param[in] cmdnum Optional number of commands which are going to be added. If zero, allocation will start at 1000.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_init(int cmdnum, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    bulk->data = (struct redis_bulk_inner *)calloc(cmdnum ? cmdnum : REDIS_MAX_BULK, sizeof *(bulk->data));
    if (!(bulk->data)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "calloc()", "");
        goto cleanup;
    }

    bulk->size = cmdnum ? cmdnum : REDIS_MAX_BULK;
    bulk->idx = 0;

cleanup:
    return err_info;
}

/**
 * @brief Start adding a command.
 *
 * @param[in] argnum Number of command's arguments.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_start(int argnum, struct redis_bulk *bulk)
{
    return srpds_docs_init(argnum, &(bulk->data[bulk->idx]));
}

/**
 * @brief Add an argument that does not require dynamic allocation.
 *
 * @param[in] argv Argument to add.
 * @param[in] argvlen Argument's length.
 * @param[out] bulk Structure containing the commands for bulk operation.
 */
static void
srpds_bulk_add_const(const char *argv, size_t argvlen, struct redis_bulk *bulk)
{
    srpds_docs_add_const(argv, argvlen, &(bulk->data[bulk->idx]));
}

/**
 * @brief Add an argument that requires dynamic allocation.
 *
 * @param[in] argv Argument to add.
 * @param[in] argvlen Argument's length.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_add_alloc(const char *argv, size_t argvlen, struct redis_bulk *bulk)
{
    return srpds_docs_add_alloc(argv, argvlen, &(bulk->data[bulk->idx]));
}

/**
 * @brief Add an argument in form of an input for vasprintf function.
 *
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @param[in] format Format string (input for vasprintf function).
 * @param ... Arguments (input for vasprintf function).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_add_format(struct redis_bulk *bulk, const char *format, ...)
{
    sr_error_info_t *err_info = NULL;
    va_list args;

    va_start(args, format);
    err_info = srpds_docs_add_format(format, args, &(bulk->data[bulk->idx]));
    va_end(args);

    return err_info;
}

/**
 * @brief Execute a bulk operation with added commands.
 *
 * @param[in] ctx Redis context.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_exec(redisContext *ctx, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    uint32_t i;

    for (i = 0; i < bulk->idx; ++i) {
        if (redisAppendCommandArgv(ctx, bulk->data[i].argnum, (const char **)bulk->data[i].argv, bulk->data[i].argvlen) !=
                REDIS_OK) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisAppendCommandArgv()", "Wrong arguments");
            goto cleanup;
        }
    }
    for (i = 0; i < bulk->idx; ++i) {
        if (redisGetReply(ctx, (void **)&reply) != REDIS_OK) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "redisGetReply()", reply->str);
            goto cleanup;
        }
        freeReplyObject(reply);
        reply = NULL;
    }

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Deallocate all resources linked with commands in bulk operation.
 *
 * @param[in,out] bulk Structure containing the commands for bulk operation.
 */
static void
srpds_bulk_destroy(struct redis_bulk *bulk)
{
    uint32_t i;

    for (i = 0; i < bulk->idx; ++i) {
        srpds_docs_destroy(&(bulk->data[i]));
    }
    free(bulk->data);
}

/**
 * @brief End adding a command.
 *
 * @param[in] ctx Redis context.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_bulk_end(redisContext *ctx, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    ++(bulk->idx);

    /* bulk exceeded the limit of commands,
     * initialize new bulk */
    if (bulk->idx >= bulk->size) {
        if ((err_info = srpds_bulk_exec(ctx, bulk))) {
            goto cleanup;
        }
        srpds_bulk_destroy(bulk);
        if ((err_info = srpds_bulk_init(0, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

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
                ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "redisConnect()", "Could not allocate Redis context");
                goto cleanup;
            }
        }

        /* authenticate if needed */
        if (strlen(SR_DS_PLG_REDIS_USERNAME)) {
            reply = redisCommand(rds_ctx, "AUTH " SR_DS_PLG_REDIS_USERNAME " " SR_DS_PLG_REDIS_PASSWORD);
            if (reply->type == REDIS_REPLY_ERROR) {
                ERRINFO(&err_info, plugin_name, SR_ERR_UNAUTHORIZED, "Authentication", reply->str);
                goto cleanup;
            }
            freeReplyObject(reply);
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
        reply = redisCommand(*ctx, "FT.CONFIG SET MAXAGGREGATERESULTS -1");
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Setting MAXAGGREGATERESULTS option", reply->str);
            goto cleanup;
        }
        freeReplyObject(reply);

        reply = redisCommand(*ctx, "FT.CONFIG SET MAXEXPANSIONS " REDIS_MAX_AGGREGATE_LIMIT);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Setting MAXEXPANSIONS option", reply->str);
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
        r = asprintf(mod_ns, "%s:%s:%s-%" PRIu32 "-%" PRIu32, srpds_ds2dsprefix(ds), sr_get_shm_prefix(), module_name, cid, sid);
    } else {
        r = asprintf(mod_ns, "%s:%s:%s", srpds_ds2dsprefix(ds), sr_get_shm_prefix(), module_name);
    }

    if (r == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
    }
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
    redisReply *reply = NULL;

    /* update only if max_order has been changed
     * aka is different from zero */
    if (max_order) {
        /* update maximum order of the list */
        reply = redisCommand(ctx, "HSET %s:meta:%s value %" PRIu64, mod_ns, path_no_pred, max_order);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Changing maximum order", reply->str);
            goto cleanup;
        }
    }

cleanup:
    freeReplyObject(reply);
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
        reply = redisCommand(ctx, "HGET %s:meta:%s value", mod_ns, path_no_pred);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting maximum order", reply->str);
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
srpds_load_prev(redisContext *ctx, const char *mod_ns, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    reply = redisCommand(ctx, "HGET %s:data:%s%s order", mod_ns, path_no_pred, prev_pred);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting order of the previous node", reply->str);
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
srpds_load_next(redisContext *ctx, const char *mod_ns, const char *prev_pred, const char *path_no_pred, uint64_t *order)
{
    /* number of arguments for the query is predetermined - 6 */
    sr_error_info_t *err_info = NULL;
    int argnum = 6;
    redisReply *reply = NULL;
    char *arg = NULL, *args_array[argnum], *prev_escaped = NULL,
            *path_no_pred_escaped = NULL;

    *order = 0;

    /* escape all special characters so that query is valid */
    if ((err_info = srpds_escape_string(plugin_name, prev_pred, &prev_escaped))) {
        goto cleanup;
    }
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, &path_no_pred_escaped))) {
        goto cleanup;
    }

    args_array[0] = "FT.AGGREGATE";
    if (asprintf(&arg, "%s:data", mod_ns) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[1] = arg;

    if (prev_pred[0] == '\0') {
        if (asprintf(&arg, "@is_prev_empty:[1 1] @path_no_pred:{%s}", path_no_pred_escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
    } else {
        if (asprintf(&arg, "@prev:{%s} @path_no_pred:{%s}", prev_escaped, path_no_pred_escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
    }
    args_array[2] = arg;

    /* retrieve only order */
    args_array[3] = "LOAD";
    args_array[4] = "1";
    args_array[5] = "order";

    reply = redisCommandArgv(ctx, argnum, (const char **)args_array, NULL);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
        goto cleanup;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
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
    free(args_array[1]);
    free(args_array[2]);
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
srpds_shift_uo_list_recursively(redisContext *ctx, const char *mod_ns, const char *path_no_pred, uint64_t next_elem_order, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    int argnum = 6;
    redisReply *reply = NULL, *reply2 = NULL;
    char *arg = NULL, *args_array[argnum], *path_no_pred_escaped = NULL;

    if ((err_info = srpds_get_maxord(ctx, mod_ns, path_no_pred, max_order))) {
        goto cleanup;
    }

    /* in case of overflow, update maxorder */
    if (*max_order < next_elem_order) {
        *max_order = next_elem_order;
    }

    /* escape all special characters so that query is valid */
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, &path_no_pred_escaped))) {
        goto cleanup;
    }

    args_array[0] = "FT.AGGREGATE";
    if (asprintf(&arg, "%s:data", mod_ns) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[1] = arg;
    if (asprintf(&arg, "@order:[%" PRIu64 " %" PRIu64 "] @path_no_pred:{%s}", next_elem_order, next_elem_order, path_no_pred_escaped) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[2] = arg;

    /* retrieve only key */
    args_array[3] = "LOAD";
    args_array[4] = "1";
    args_array[5] = "__key";

    reply = redisCommandArgv(ctx, argnum, (const char **)args_array, NULL);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
        goto cleanup;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
        goto cleanup;
    }

    if (reply->element[0]->integer == 1) {
        /* An element with such order has been found, shift all elements
         * after this element */
        if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_elem_order + 1, max_order))) {
            goto cleanup;
        }

        /* on [1] -> [1] is the key of the found element */
        reply2 = redisCommand(ctx, "HSET %s order %" PRIu64, reply->element[1]->element[1]->str, next_elem_order + 1);
        if (reply2->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Setting order", reply2->str);
            goto cleanup;
        }
    }

cleanup:
    free(path_no_pred_escaped);
    free(args_array[1]);
    free(args_array[2]);
    freeReplyObject(reply);
    freeReplyObject(reply2);
    return err_info;
}

/**
 * @brief Insert a new userordered element into the list or leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of a list/leaf-list instance.
 * @param[in] value Value of the node.
 * @param[in] prev Value of a previous element.
 * @param[in] prev_pred Value of a previous element in predicate.
 * @param[in] order Order of the element.
 * @param[in] path_no_pred Path of a list/leaf-list instance without a predicate.
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_insert_uo_element(redisContext *ctx, const char *mod_ns, struct lyd_node *node, const char *module_name,
        const char *path, const char *value, const char *prev, const char *prev_pred, uint64_t order,
        const char *path_no_pred, const char *path_modif)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;
    char *keys = NULL, *idx = NULL, *type = NULL, *order_str = NULL,
            *is_prev_empty_str = NULL;
    int argnum = 22;
    const char *argv[argnum];
    size_t argvlen[argnum];
    uint32_t keys_length = 0;

    /* insert an element */
    /* we need is_prev_empty field since we cannot check if prev is empty or not */
    switch (node->schema->nodetype) {
    case LYS_LIST:
        if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
            goto cleanup;
        }

        argv[0] = "HSET";
        argvlen[0] = 4;
        if (asprintf(&idx, "%s:data:%s", mod_ns, path) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        argv[1] = idx;
        argvlen[1] = strlen(idx);
        argv[2] = "path";
        argvlen[2] = 4;
        argv[3] = path;
        argvlen[3] = strlen(path);
        argv[4] = "name";
        argvlen[4] = 4;
        argv[5] = node->schema->name;
        argvlen[5] = strlen(node->schema->name);
        argv[6] = "type";
        argvlen[6] = 4;
        if (asprintf(&type, "%d", SRPDS_DB_LY_LIST_UO) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        argv[7] = type; // SRPDS_DB_LY_LIST_UO
        argvlen[7] = strlen(type);
        argv[8] = "module_name";
        argvlen[8] = 11;
        argv[9] = module_name;
        argvlen[9] = strlen(module_name);
        argv[10] = "keys";
        argvlen[10] = 4;
        argv[11] = keys;
        argvlen[11] = keys_length;
        argv[12] = "order";
        argvlen[12] = 5;
        if (asprintf(&order_str, "%" PRIu64, order) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        argv[13] = order_str;
        argvlen[13] = strlen(order_str);
        argv[14] = "path_no_pred";
        argvlen[14] = 12;
        argv[15] = path_no_pred;
        argvlen[15] = strlen(path_no_pred);
        argv[16] = "prev";
        argvlen[16] = 4;
        argv[17] = prev_pred;
        argvlen[17] = strlen(prev_pred);
        argv[18] = "is_prev_empty";
        argvlen[18] = 13;
        if (asprintf(&is_prev_empty_str, "%d", (prev[0] == '\0') ? 1 : 0) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        argv[19] = is_prev_empty_str;
        argvlen[19] = strlen(is_prev_empty_str);
        argv[20] = "path_modif";
        argvlen[20] = 10;
        argv[21] = path_modif;
        argvlen[21] = strlen(path_modif);

        reply = redisCommandArgv(ctx, argnum, argv, argvlen);
        break;
    case LYS_LEAFLIST:
        reply = redisCommand(ctx, "HSET %s:data:%s path %s name %s type %d module_name %s dflt_flag %d"
                " value %s order %" PRIu64 " path_no_pred %s prev %s is_prev_empty %d path_modif %s",
                mod_ns, path, path, node->schema->name, SRPDS_DB_LY_LEAFLIST_UO, module_name, 0, value,
                order, path_no_pred, prev_pred, (prev[0] == '\0') ? 1 : 0, path_modif);
        break;
    }

    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Inserting userordered element", reply->str);
        goto cleanup;
    }

cleanup:
    free(keys);
    free(idx);
    free(type);
    free(order_str);
    free(is_prev_empty_str);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Delete a userordered element from the list or leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path of a list/leaf-list instance.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_element(redisContext *ctx, const char *mod_ns, const char *path)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    /* delete the element */
    reply = redisCommand(ctx, "DEL %s:data:%s", mod_ns, path);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Deleting user ordered element", reply->str);
        goto cleanup;
    }

cleanup:
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
srpds_change_next_element(redisContext *ctx, const char *mod_ns, const char *path_no_pred, const char *prev_pred, const char *new_prev_pred)
{
    sr_error_info_t *err_info = NULL;
    int argnum = 6;
    redisReply *reply = NULL, *reply2 = NULL;
    char *arg = NULL, *args_array[argnum], *prev_escaped = NULL, *path_no_pred_escaped = NULL;

    if ((err_info = srpds_escape_string(plugin_name, prev_pred, &prev_escaped))) {
        goto cleanup;
    }
    if ((err_info = srpds_escape_string(plugin_name, path_no_pred, &path_no_pred_escaped))) {
        goto cleanup;
    }

    args_array[0] = "FT.AGGREGATE";
    if (asprintf(&arg, "%s:data", mod_ns) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[1] = arg;

    /* we need is_prev_empty field since we cannot check if prev is empty or not */
    if (prev_pred[0] == '\0') {
        if (asprintf(&arg, "@is_prev_empty:[1 1] @path_no_pred:{%s}", path_no_pred_escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
    } else {
        if (asprintf(&arg, "@prev:{%s} @path_no_pred:{%s}", prev_escaped, path_no_pred_escaped) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
    }
    args_array[2] = arg;
    args_array[3] = "LOAD";
    args_array[4] = "1";
    args_array[5] = "__key";

    reply = redisCommandArgv(ctx, argnum, (const char **)args_array, NULL);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
        goto cleanup;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
        goto cleanup;
    }

    /* change the next element */
    if (reply->elements == 2) {
        reply2 = redisCommand(ctx, "HSET %s prev %s is_prev_empty %d", reply->element[1]->element[1]->str,
                new_prev_pred, (new_prev_pred[0] == '\0') ? 1 : 0);
        if (reply2->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Changing next element", reply2->str);
            goto cleanup;
        }
    }

cleanup:
    free(prev_escaped);
    free(path_no_pred_escaped);
    free(args_array[1]);
    free(args_array[2]);
    freeReplyObject(reply2);
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Insert a user-ordered element into a list or a leaf-list in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of the user-ordered element.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] value Value of the user-ordered element.
 * @param[in] prev Value of the previous element.
 * @param[in] prev_pred Value of the previous in a predicate, e.g. [.=''].
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @param[out] max_order Changed maximum order.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_uo_op(redisContext *ctx, const char *mod_ns, struct lyd_node *node, const char *module_name,
        const char *path, const char *path_no_pred, const char *predicate, const char *value, const char *prev,
        const char *prev_pred, const char *path_modif, uint64_t *max_order)
{
    sr_error_info_t *err_info = NULL;
    uint64_t prev_order = 0, next_order = 0;

    /* there is a previous element */
    if (strcmp(prev, "")) {
        /* load previous,
         * get order of the previous element */
        if ((err_info = srpds_load_prev(ctx, mod_ns, prev_pred, path_no_pred, &prev_order))) {
            goto cleanup;
        }

        /* load next
         * get order of the next element */
        if ((err_info = srpds_load_next(ctx, mod_ns, prev_pred, path_no_pred, &next_order))) {
            goto cleanup;
        }

        if (!next_order) {
            /* get max order for lists and leaf-lists */
            if ((err_info = srpds_get_maxord(ctx, mod_ns, path_no_pred, max_order))) {
                goto cleanup;
            }

            srpds_inc_maxord(max_order);

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    *max_order, path_no_pred, path_modif))) {
                goto cleanup;
            }
        } else if (next_order - prev_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev_pred, predicate))) {
                goto cleanup;
            }

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    next_order, path_no_pred, path_modif))) {
                goto cleanup;
            }
        } else {
            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev_pred, predicate))) {
                goto cleanup;
            }

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    (uint64_t)(prev_order + (next_order - prev_order) / 2), path_no_pred, path_modif))) {
                goto cleanup;
            }
        }
        /* there is no previous element */
    } else {
        /* get order of the next element */
        if ((err_info = srpds_load_next(ctx, mod_ns, prev_pred, path_no_pred, &next_order))) {
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

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    SRPDS_DB_UO_ELEMS_GAP_SIZE, path_no_pred, path_modif))) {
                goto cleanup;
            }
        } else if (next_order == 1) {
            /* shift next elements by one recursively */
            if ((err_info = srpds_shift_uo_list_recursively(ctx, mod_ns, path_no_pred, next_order, max_order))) {
                goto cleanup;
            }

            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev_pred, predicate))) {
                goto cleanup;
            }

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    next_order, path_no_pred, path_modif))) {
                goto cleanup;
            }
        } else {
            /* set new prev field of the next element */
            if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, prev_pred, predicate))) {
                goto cleanup;
            }

            if ((err_info = srpds_insert_uo_element(ctx, mod_ns, node, module_name, path, value, prev, prev_pred,
                    (uint64_t)(next_order / 2), path_no_pred, path_modif))) {
                goto cleanup;
            }
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
 * @param[in] path Path of the user-ordered element.
 * @param[in] path_no_pred Path without a predicate of the user-ordered element.
 * @param[in] predicate Predicate of the user-ordered element.
 * @param[in] orig_prev_pred Predicate of a previous element.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_uo_op(redisContext *ctx, const char *mod_ns, const char *path, const char *path_no_pred, const char *predicate,
        const char *orig_prev_pred)
{
    sr_error_info_t *err_info = NULL;

    /* set new prev field of the next element */
    if ((err_info = srpds_change_next_element(ctx, mod_ns, path_no_pred, predicate, orig_prev_pred))) {
        goto cleanup;
    }

    if ((err_info = srpds_delete_uo_element(ctx, mod_ns, path))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to a data node.
 * @param[in] add_or_remove Whether the default flag should be added or removed.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_change_default_flag(redisContext *ctx, const char *mod_ns, const char *path, int add_or_remove, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if ((err_info = srpds_bulk_start(4, bulk))) {
        goto cleanup;
    }
    srpds_bulk_add_const("HSET", 4, bulk);
    if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
        goto cleanup;
    }
    srpds_bulk_add_const("dflt_flag", 9, bulk);
    if ((err_info = srpds_bulk_add_format(bulk, "%d", add_or_remove))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_end(ctx, bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] ctx Redis context.
 * @param[in] node Data node.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to a data node.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_update_default_flag(redisContext *ctx, struct lyd_node *node, const char *mod_ns, const char *path,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (!strcmp(lyd_get_meta_value(lyd_find_meta(node->meta, NULL, "yang:orig-default")), "true")) {
        if (!(node->flags & LYD_DEFAULT)) {
            /* remove default flag */
            err_info = srpds_change_default_flag(ctx, mod_ns, path, 0, bulk);
        }
    } else {
        if (node->flags & LYD_DEFAULT) {
            /* add default flag */
            err_info = srpds_change_default_flag(ctx, mod_ns, path, 1, bulk);
        }
    }

    return err_info;
}

/**
 * @brief Change the default flag of a node to true.
 *
 * @param[in] ctx Redis context.
 * @param[in] node Data node.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to a data node.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op_default_flag(redisContext *ctx, struct lyd_node *node, const char *mod_ns, const char *path,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM)) {
        goto cleanup;
    }

    if (node->flags & LYD_DEFAULT) {
        /* add default flag */
        err_info = srpds_change_default_flag(ctx, mod_ns, path, 1, bulk);
    }

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] ctx Redis context.
 * @param[in] node Data node.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to a data node.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_none_op_default_flag(redisContext *ctx, struct lyd_node *node, const char *mod_ns, const char *path,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (!(node->schema->nodetype & LYD_NODE_TERM)) {
        goto cleanup;
    }

    err_info = srpds_update_default_flag(ctx, node, mod_ns, path, bulk);

cleanup:
    return err_info;
}

/**
 * @brief Change the default flag of a node to the opposite.
 *
 * @param[in] ctx Redis context.
 * @param[in] node Data node.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to a data node.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op_default_flag(redisContext *ctx, struct lyd_node *node, const char *mod_ns, const char *path,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    /* for userordered leaflists replace operation can never change the default flag */
    if (!(node->schema->nodetype & LYD_NODE_TERM) ||
            ((node->schema->nodetype & LYS_LEAFLIST) && lysc_is_userordered(node->schema))) {
        goto cleanup;
    }

    err_info = srpds_update_default_flag(ctx, node, mod_ns, path, bulk);

cleanup:
    return err_info;
}

/**
 * @brief Diff operation create.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
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
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_op(redisContext *ctx, const char *mod_ns, struct lyd_node *node, const char *module_name,
        const char *path, const char *path_no_pred, const char *predicate, const char *path_modif,
        const char *value, const char *prev, const char *prev_pred, int32_t valtype, uint64_t *max_order,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;
    char *keys = NULL;
    uint32_t keys_length = 0;

    if (lysc_is_userordered(node->schema)) {
        /* insert a new element into the user-ordered list */
        if ((err_info = srpds_create_uo_op(ctx, mod_ns, node, module_name, path, path_no_pred, predicate, value, prev,
                prev_pred, path_modif, max_order))) {
            goto cleanup;
        }
    } else {
        switch (node->schema->nodetype) {
        case LYS_CONTAINER:
            if ((err_info = srpds_bulk_start(12, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(node->schema->name, strlen(node->schema->name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_CONTAINER))) {
                goto cleanup;
            }
            srpds_bulk_add_const("module_name", 11, bulk);
            if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path_modif", 10, bulk);
            if ((err_info = srpds_bulk_add_alloc(path_modif, strlen(path_modif), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }
            break;
        case LYS_LIST:
            if ((err_info = srpds_concat_key_values(plugin_name, node, &keys, &keys_length))) {
                goto cleanup;
            }

            if ((err_info = srpds_bulk_start(14, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(node->schema->name, strlen(node->schema->name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_LIST))) {
                goto cleanup;
            }
            srpds_bulk_add_const("module_name", 11, bulk);
            if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("keys", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(keys, keys_length, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path_modif", 10, bulk);
            if ((err_info = srpds_bulk_add_alloc(path_modif, strlen(path_modif), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }

            free(keys);
            keys = NULL;
            break;
        case LYS_LEAF:
        case LYS_LEAFLIST:
            if ((err_info = srpds_bulk_start(16, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(node->schema->name, strlen(node->schema->name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_TERM))) {
                goto cleanup;
            }
            srpds_bulk_add_const("module_name", 11, bulk);
            if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("dflt_flag", 9, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", 0))) {
                goto cleanup;
            }
            srpds_bulk_add_const("value", 5, bulk);
            if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path_modif", 10, bulk);
            if ((err_info = srpds_bulk_add_alloc(path_modif, strlen(path_modif), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }
            break;
        case LYS_ANYDATA:
        case LYS_ANYXML:
            if ((err_info = srpds_bulk_start(18, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(node->schema->name, strlen(node->schema->name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_ANY))) {
                goto cleanup;
            }
            srpds_bulk_add_const("module_name", 11, bulk);
            if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("dflt_flag", 9, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", 0))) {
                goto cleanup;
            }
            srpds_bulk_add_const("value", 5, bulk);
            if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("valtype", 7, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%" PRId32, valtype))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path_modif", 10, bulk);
            if ((err_info = srpds_bulk_add_alloc(path_modif, strlen(path_modif), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }
            break;
        default:
            break;
        }
    }

    /* default nodes */
    if ((err_info = srpds_create_op_default_flag(ctx, node, mod_ns, path, bulk))) {
        goto cleanup;
    }

cleanup:
    free(keys);
    return err_info;
}

/**
 * @brief Diff operation delete.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Current data node in the diff.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] orig_prev_pred Original value of the node in predicate.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_op(redisContext *ctx, const char *mod_ns, struct lyd_node *node, const char *path, const char *path_no_pred,
        const char *predicate, const char *orig_prev_pred, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (lysc_is_userordered(node->schema)) {
        /* delete an element from the user-ordered list */
        if ((err_info = srpds_delete_uo_op(ctx, mod_ns, path, path_no_pred, predicate, orig_prev_pred))) {
            goto cleanup;
        }
    } else {
        /* delete all fields within the key */
        if ((err_info = srpds_bulk_start(2, bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("DEL", 3, bulk);
        if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, bulk))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

/**
 * @brief Diff operation replace.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] node Current data node in the diff.
 * @param[in] module_name Name of the module the node belongs to.
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @param[in] predicate Predicate of the data node.
 * @param[in] value Value of the node.
 * @param[in] prev Value of the node before this node.
 * @param[in] prev_pred Value of the node before this node in predicate.
 * @param[in] orig_prev_pred Original value of the node in predicate.
 * @param[in] path_modif Modified path with ' ' instead of '/' for loading purposes.
 * @param[in,out] max_order Maximum order of the list or leaf-list.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_replace_op(redisContext *ctx, const char *mod_ns, struct lyd_node *node, const char *module_name, const char *path,
        const char *path_no_pred, const char *predicate, const char *value, const char *prev, const char *prev_pred,
        const char *orig_prev_pred, const char *path_modif, uint64_t *max_order, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if (lysc_is_userordered(node->schema)) {
        /* delete an element from the user-ordered list */
        if ((err_info = srpds_delete_uo_op(ctx, mod_ns, path, path_no_pred, predicate, orig_prev_pred))) {
            goto cleanup;
        }

        /* insert a new element into the user-ordered list */
        if ((err_info = srpds_create_uo_op(ctx, mod_ns, node, module_name, path, path_no_pred, predicate, value, prev,
                prev_pred, path_modif, max_order))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_bulk_start(4, bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("HSET", 4, bulk);
        if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
            goto cleanup;
        }
        srpds_bulk_add_const("value", 5, bulk);
        if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, bulk))) {
            goto cleanup;
        }
    }

    /* default nodes */
    if ((err_info = srpds_replace_op_default_flag(ctx, node, mod_ns, path, bulk))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load the whole diff and store the data in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] node Current data node in the diff.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] parent_op Operation on the node's parent.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_diff_recursively(redisContext *ctx, const struct lyd_node *node, const char *mod_ns, char parent_op,
        struct redis_bulk *bulk)
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
        if ((err_info = srpds_get_predicate(plugin_name, sibling, &predicate, &path, &path_no_pred))) {
            goto cleanup;
        }

        /* get modified version of path and path_no_pred */
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
            module_name = "";
        }

        switch (this_op) {
        case 'n':
            /* default nodes */
            if ((err_info = srpds_none_op_default_flag(ctx, sibling, mod_ns, path, bulk))) {
                goto cleanup;
            }
            break;
        case 'c':
            if ((err_info = srpds_create_op(ctx, mod_ns, sibling, module_name, path, path_no_pred, predicate, path_modif,
                    value, prev, prev_pred, valtype, &max_order, bulk))) {
                goto cleanup;
            }
            break;
        case 'd':
            if ((err_info = srpds_delete_op(ctx, mod_ns, sibling, path, path_no_pred, predicate,
                    orig_prev_pred ? orig_prev_pred : "", bulk))) {
                goto cleanup;
            }
            break;
        case 'r':
            if ((err_info = srpds_replace_op(ctx, mod_ns, sibling, module_name, path, path_no_pred, predicate, value,
                    prev, prev_pred, orig_prev_pred, path_modif, &max_order, bulk))) {
                goto cleanup;
            }
            break;
        case 0:
            ERRINFO(&err_info, plugin_name, SR_ERR_UNSUPPORTED, "Operation for a node", "Unsupported operation");
            goto cleanup;
            break;
        }

        /* reset the max_order if the next sibling
         * is from a different list or if the next sibling does not exist */
        if (lysc_is_userordered(sibling->schema) && ((sibling->next &&
                (sibling->schema->name != sibling->next->schema->name)) || !(sibling->next))) {
            /* update max order for lists and leaf-lists */
            if ((err_info = srpds_set_maxord(ctx, mod_ns, path_no_pred, max_order))) {
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
            if ((err_info = srpds_store_diff_recursively(ctx, child, mod_ns, this_op, bulk))) {
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
 * @brief Add new metadata to store in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] meta Metadata to store.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to the node with metadata.
 * @param[out] order Order of the nodes.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_meta(redisContext *ctx, struct lyd_meta *meta, const char *mod_ns, const char *path, uint64_t *order,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;
    const char *meta_value;

    while (meta) {
        ++*order;
        meta_value = lyd_get_meta_value(meta);

        /* skip yang:lyds_tree metadata, this is libyang specific data */
        if (strcmp(meta->annotation->module->name, "yang") || strcmp(meta->name, "lyds_tree")) {
            /* create new metadata */
            if ((err_info = srpds_bulk_start(12, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s:%s:%s", mod_ns, path, meta->annotation->module->name, meta->name))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:%s", meta->annotation->module->name, meta->name))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_META))) {
                goto cleanup;
            }
            srpds_bulk_add_const("order", 5, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                goto cleanup;
            }
            srpds_bulk_add_const("value", 5, bulk);
            if ((err_info = srpds_bulk_add_alloc(meta_value, strlen(meta_value), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }
        }

        meta = meta->next;
    }

cleanup:
    return err_info;
}

/**
 * @brief Add new attributes to store in the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] attr Attributes to store.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] path Path to the node with attributes.
 * @param[out] order Order of the nodes.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_add_attr(redisContext *ctx, struct lyd_attr *attr, const char *mod_ns, const char *path, uint64_t *order,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    while (attr) {
        ++*order;

        /* opaque node has to have a JSON format */
        assert(attr->format == LY_VALUE_JSON);

        /* skip yang:lyds_tree attributes, this is libyang specific data */
        if (strcmp(attr->name.module_name, "yang") || strcmp(attr->name.name, "lyds_tree")) {
            /* create new attribute */
            if ((err_info = srpds_bulk_start(12, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s:%s:%s", mod_ns, path, attr->name.module_name, attr->name.name))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:%s", attr->name.module_name, attr->name.name))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_ATTR))) {
                goto cleanup;
            }
            srpds_bulk_add_const("order", 5, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                goto cleanup;
            }
            srpds_bulk_add_const("value", 5, bulk);
            if ((err_info = srpds_bulk_add_alloc(attr->value, strlen(attr->value), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }
        }

        attr = attr->next;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load the whole data tree and store the data in the database (only for operational).
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_data Whole data tree.
 * @param[in] mod_ns Database prefix for the module.
 * @param[out] order Order of the nodes.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_store_oper_recursively(redisContext *ctx, const struct lyd_node *mod_data, const char *mod_ns, uint64_t *order,
        struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;
    const struct lyd_node *sibling = mod_data;
    struct lyd_node *child = NULL;
    struct lyd_node_opaq *opaque = NULL; // for opaque nodes
    char *path = NULL, *any_value = NULL, *keys = NULL, idx_str[24];
    uint32_t keys_length = 0, discard_items_idx = 1;
    const char *module_name = NULL, *value = NULL;

    while (sibling) {
        ++*order;

        /* get path */
        path = lyd_path(sibling, LYD_PATH_STD, NULL, 0);
        if (!path) {
            ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_path()", "");
            return err_info;
        }

        /* get value */
        if (sibling->schema && (sibling->schema->nodetype & LYD_NODE_ANY)) {
            /* lyd_node_any */
            if (lyd_any_value_str(sibling, &any_value) != LY_SUCCESS) {
                ERRINFO(&err_info, plugin_name, SR_ERR_LY, "lyd_any_value_str()", "");
                goto cleanup;
            }
            value = any_value;
        } else {
            /* node values, opaque node values and the rest */
            value = lyd_get_value(sibling);
        }

        /* get module name */
        if (!sibling->schema) {
            /* opaque node has to have a JSON format */
            opaque = ((struct lyd_node_opaq *)sibling);
            assert(opaque->format == LY_VALUE_JSON);
            module_name = opaque->name.module_name;
        } else if ((sibling->parent == NULL) || strcmp(sibling->schema->module->name, sibling->parent->schema->module->name)) {
            module_name = sibling->schema->module->name;
        } else {
            module_name = "";
        }

        /* create all data */
        if (sibling->schema) {
            switch (sibling->schema->nodetype) {
            case LYS_CONTAINER:
                if ((err_info = srpds_bulk_start(12, bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("HSET", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("path", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("name", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(sibling->schema->name, strlen(sibling->schema->name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("type", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_CONTAINER))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("order", 5, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("module_name", 11, bulk);
                if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                    goto cleanup;
                }
                if ((err_info = srpds_bulk_end(ctx, bulk))) {
                    goto cleanup;
                }
                break;
            case LYS_LIST:     /* does not matter if this is user-ordered list or not */
                if ((err_info = srpds_concat_key_values(plugin_name, sibling, &keys, &keys_length))) {
                    goto cleanup;
                }

                if ((err_info = srpds_bulk_start(14, bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("HSET", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("path", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("name", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(sibling->schema->name, strlen(sibling->schema->name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("type", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_LIST))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("order", 5, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("module_name", 11, bulk);
                if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("keys", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(keys, keys_length, bulk))) {
                    goto cleanup;
                }
                if ((err_info = srpds_bulk_end(ctx, bulk))) {
                    goto cleanup;
                }
                break;
            case LYS_LEAF:
            case LYS_LEAFLIST:  /* does not matter if this is user-ordered leaf-list or not */
                if ((err_info = srpds_bulk_start(16, bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("HSET", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("path", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("name", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(sibling->schema->name, strlen(sibling->schema->name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("type", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_TERM))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("order", 5, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("module_name", 11, bulk);
                if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("value", 5, bulk);
                if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("dflt_flag", 9, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", sibling->flags & LYD_DEFAULT))) {
                    goto cleanup;
                }
                if ((err_info = srpds_bulk_end(ctx, bulk))) {
                    goto cleanup;
                }
                break;
            case LYS_ANYDATA:
            case LYS_ANYXML:
                if ((err_info = srpds_bulk_start(18, bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("HSET", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("path", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("name", 4, bulk);
                if ((err_info = srpds_bulk_add_alloc(sibling->schema->name, strlen(sibling->schema->name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("type", 4, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_ANY))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("order", 5, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("module_name", 11, bulk);
                if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("value", 5, bulk);
                if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("dflt_flag", 9, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%d", sibling->flags & LYD_DEFAULT))) {
                    goto cleanup;
                }
                srpds_bulk_add_const("valtype", 7, bulk);
                if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu32, (((struct lyd_node_any *)sibling)->value_type == LYD_ANYDATA_JSON)))) {
                    goto cleanup;
                }
                if ((err_info = srpds_bulk_end(ctx, bulk))) {
                    goto cleanup;
                }
                break;
            }

            /* add metadata */
            if ((err_info = srpds_add_meta(ctx, sibling->meta, mod_ns, path, order, bulk))) {
                goto cleanup;
            }
        } else {
            /* add index */
            sprintf(idx_str, "[%" PRIu32 "]", discard_items_idx++);
            path = realloc(path, strlen(path) + strlen(idx_str) + 1);
            strcat(path, idx_str);

            if ((err_info = srpds_bulk_start(14, bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("HSET", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%s:data:%s", mod_ns, path))) {
                goto cleanup;
            }
            srpds_bulk_add_const("path", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(path, strlen(path), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("name", 4, bulk);
            if ((err_info = srpds_bulk_add_alloc(opaque->name.name, strlen(opaque->name.name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("type", 4, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%d", SRPDS_DB_LY_OPAQUE))) {
                goto cleanup;
            }
            srpds_bulk_add_const("order", 5, bulk);
            if ((err_info = srpds_bulk_add_format(bulk, "%" PRIu64, *order))) {
                goto cleanup;
            }
            srpds_bulk_add_const("module_name", 11, bulk);
            if ((err_info = srpds_bulk_add_alloc(module_name, strlen(module_name), bulk))) {
                goto cleanup;
            }
            srpds_bulk_add_const("value", 5, bulk);
            if ((err_info = srpds_bulk_add_alloc(value, strlen(value), bulk))) {
                goto cleanup;
            }
            if ((err_info = srpds_bulk_end(ctx, bulk))) {
                goto cleanup;
            }

            /* add attributes */
            if ((err_info = srpds_add_attr(ctx, opaque->attr, mod_ns, path, order, bulk))) {
                goto cleanup;
            }
        }

        if ((child = lyd_child_no_keys(sibling))) {
            if ((err_info = srpds_store_oper_recursively(ctx, child, mod_ns, order, bulk))) {
                goto cleanup;
            }
        }

        sibling = sibling->next;

        free(path);
        free(any_value);
        free(keys);
        path = NULL;
        any_value = NULL;
        keys = NULL;
    }

cleanup:
    free(path);
    free(any_value);
    free(keys);
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
srpds_set_flags(redisContext *ctx, const char *mod_ns, sr_datastore_t ds, struct timespec *spec, int candidate_modified)
{
    sr_error_info_t *err_info = NULL;
    struct redis_bulk bulk = {0};

    if ((err_info = srpds_bulk_init(3, &bulk))) {
        goto cleanup;
    }

    /* set last-modified flag in seconds */
    if ((err_info = srpds_bulk_start(3, &bulk))) {
        goto cleanup;
    }
    srpds_bulk_add_const("SET", 3, &bulk);
    if ((err_info = srpds_bulk_add_format(&bulk, "%s:glob:last-modified-sec", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_add_format(&bulk, "%" PRId64, spec->tv_sec))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_end(ctx, &bulk))) {
        goto cleanup;
    }

    /* set last-modified flag in nanoseconds */
    if ((err_info = srpds_bulk_start(3, &bulk))) {
        goto cleanup;
    }
    srpds_bulk_add_const("SET", 3, &bulk);
    if ((err_info = srpds_bulk_add_format(&bulk, "%s:glob:last-modified-nsec", mod_ns))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_add_format(&bulk, "%" PRId64, spec->tv_nsec))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_end(ctx, &bulk))) {
        goto cleanup;
    }

    /* set candidate-modified flag */
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_bulk_start(3, &bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("SET", 3, &bulk);
        if ((err_info = srpds_bulk_add_format(&bulk, "%s:glob:candidate-modified", mod_ns))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_add_format(&bulk, "%d", candidate_modified))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, &bulk))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    srpds_bulk_destroy(&bulk);
    return err_info;
}

/**
 * @brief Delete a specific piece of data from the database.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] to_del Part after the prefix of the key to delete.
 * @param[out] bulk Structure containing the commands for bulk operation.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_delete_one(redisContext *ctx, const char *mod_ns, const char *to_del, struct redis_bulk *bulk)
{
    sr_error_info_t *err_info = NULL;

    if ((err_info = srpds_bulk_start(2, bulk))) {
        goto cleanup;
    }
    srpds_bulk_add_const("DEL", 3, bulk);
    if ((err_info = srpds_bulk_add_format(bulk, "%s:%s", mod_ns, to_del))) {
        goto cleanup;
    }
    if ((err_info = srpds_bulk_end(ctx, bulk))) {
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
    struct redis_bulk bulk = {0};

    if ((err_info = srpds_bulk_init(6, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_delete_one(ctx, mod_ns, "glob:last-modified-sec", &bulk))) {
        goto cleanup;
    }
    if ((err_info = srpds_delete_one(ctx, mod_ns, "glob:last-modified-nsec", &bulk))) {
        goto cleanup;
    }
    if (ds == SR_DS_CANDIDATE) {
        if ((err_info = srpds_delete_one(ctx, mod_ns, "glob:candidate-modified", &bulk))) {
            goto cleanup;
        }
    }
    if ((err_info = srpds_delete_one(ctx, mod_ns, "perm:owner", &bulk))) {
        goto cleanup;
    }
    if ((err_info = srpds_delete_one(ctx, mod_ns, "perm:group", &bulk))) {
        goto cleanup;
    }
    if ((err_info = srpds_delete_one(ctx, mod_ns, "perm:perm", &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    srpds_bulk_destroy(&bulk);
    return err_info;
}

/**
 * @brief Create all necessary indices.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] is_oper Whether the indices are created for Operational datastore.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_create_indices(redisContext *ctx, const char *mod_ns, int is_oper)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    /* index for data */
    if (is_oper) {
        reply = redisCommand(ctx, "FT.CREATE %s:data "
                "ON HASH PREFIX 1 %s:data: "
                "STOPWORDS 0 "
                "SCHEMA path TAG CASESENSITIVE "
                "name TAG CASESENSITIVE "
                "type NUMERIC "
                "order NUMERIC SORTABLE "
                "module_name TAG CASESENSITIVE "
                "value TAG CASESENSITIVE "
                "valtype NUMERIC "
                "keys TAG CASESENSITIVE "
                "dflt_flag NUMERIC ", mod_ns, mod_ns);
    } else {
        reply = redisCommand(ctx, "FT.CREATE %s:data "
                "ON HASH PREFIX 1 %s:data: "
                "STOPWORDS 0 "
                "SCHEMA path TAG CASESENSITIVE "
                "name TAG CASESENSITIVE "
                "type NUMERIC "
                "module_name TAG CASESENSITIVE "
                "dflt_flag NUMERIC "
                "keys TAG CASESENSITIVE "
                "value TAG CASESENSITIVE "
                "valtype NUMERIC "
                "order NUMERIC "
                "path_no_pred TAG CASESENSITIVE "
                "prev TAG CASESENSITIVE "
                "is_prev_empty NUMERIC "
                "path_modif TAG CASESENSITIVE SORTABLE UNF ", mod_ns, mod_ns);
    }
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Creating index", reply->str);
        goto cleanup;
    }

    /* index for maxorder */
    if (!is_oper) {
        freeReplyObject(reply);
        reply = redisCommand(ctx, "FT.CREATE %s:meta "
                "ON HASH PREFIX 1 %s:meta: "
                "STOPWORDS 0 "
                "SCHEMA value NUMERIC", mod_ns, mod_ns);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Creating index", reply->str);
            goto cleanup;
        }
    }

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Load data from the database and execute a command on them.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] index_type Type of the data to retrieve (meta or data).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_del(redisContext *ctx, const char *mod_ns, const char *index_type)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    reply = redisCommand(ctx, "EVAL %s 1 %s:%s",
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

    if ((reply->type == REDIS_REPLY_STRING) && strstr(mod_ns, "operational") && strstr(reply->str, "no such index")) {
        /* empty data, the index has not been created yet, do so now BUG is never deleted */
        err_info = srpds_create_indices(ctx, mod_ns, 1);
    } else if ((reply->type == REDIS_REPLY_ERROR) || (reply->type == REDIS_REPLY_STRING)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "EVAL", reply->str);
        goto cleanup;
    }

cleanup:
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Load data (only :data and :meta) from the database and delete them.
 *
 * @param[in] ctx Redis context.
 * @param[in] ds Datastore in which to delete data.
 * @param[in] mod_ns Database prefix for the module.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_del_data(redisContext *ctx, sr_datastore_t ds, const char *mod_ns)
{
    sr_error_info_t *err_info = NULL;

    /* operational ds does not store max order */
    if (ds != SR_DS_OPERATIONAL) {
        if ((err_info = srpds_load_and_del(ctx, mod_ns, "meta"))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_load_and_del(ctx, mod_ns, "data"))) {
        goto cleanup;
    }

cleanup:
    return err_info;
}

/**
 * @brief Load data from the database and execute a command on them.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] index_type Type of the data to retrieve (meta or data).
 * @param[in] trg_ds Target datastore.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_and_copy(redisContext *ctx, const char *mod_ns, const char *index_type, const char *trg_ds)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    reply = redisCommand(ctx, "EVAL %s 1 %s:%s %s",
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

    if ((reply->type == REDIS_REPLY_ERROR) || (reply->type == REDIS_REPLY_STRING)) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "EVAL", reply->str);
        goto cleanup;
    }

cleanup:
    freeReplyObject(reply);
    return err_info;
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

    if ((err_info = srpds_load_and_copy(ctx, mod_ns_src, "meta", trg_ds))) {
        goto cleanup;
    }

    if ((err_info = srpds_load_and_copy(ctx, mod_ns_src, "data", trg_ds))) {
        goto cleanup;
    }

cleanup:
    return err_info;
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

        if ((err_info = srpds_escape_string(plugin_name, path, &escaped_path))) {
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
            if ((err_info = srpds_escape_string(plugin_name, path, &escaped_path))) {
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
        if ((err_info = srpds_escape_string(plugin_name, "/sysrepo:discard-items", &escaped_path))) {
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
 * @brief Load all data (only :data and :meta) from the database and store them inside the lyd_node structure (only for operational datastore).
 *
 * @param[in] ctx Redis context.
 * @param[in] mod Given module.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] xpath_filter Query filter composed of load XPaths to speed up the loading process.
 * @param[out] mod_data Retrieved module data from the database.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_load_oper(redisContext *ctx, const struct lys_module *mod, const char *mod_ns, const char *xpath_filter,
        struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    const char *path, *name, *module_name = NULL, *value = NULL;
    uint32_t i, j;
    uint64_t type, valtype = 0;
    int dflt_flag = 0;
    char **keys = NULL;
    uint32_t *lengths = NULL;

    redisReply *reply = NULL, *partial = NULL;
    long long cursor;
    int argnum = 15;
    char *args_array[argnum], *arg = NULL;

    struct lyd_node **parent_nodes = NULL;
    size_t pnodes_size = 0;

    /*
    *   Loading multiple different sets of data
    *
    *   Load Oper
    *   | 1) containers (LYS_CONTAINER)
    *   |    Dataset [ path | name | type | order | module_name ]
    *   |
    *   | 2) lists (LYS_LIST)
    *   |    Dataset [ path | name | type | order | module_name | keys ]
    *   |
    *   | 3) leafs and leaf-lists (LYS_LEAF and LYS_LEAFLIST)
    *   |    Dataset [ path | name | type | order | module_name | value | dflt_flag ]
    *   |
    *   | 4) anydata and anyxml (LYS_ANYDATA and LYS_ANYXML)
    *   |    Dataset [ path | name | type | order | module_name | value | dflt_flag | valtype ]
    *   |
    *   | 7) opaque nodes
    *   |    Dataset [ path | name | type | order | module_name | value ]
    *   |
    *   | 8/9) metadata and attributes
    *   |
    *   | module_name = "" - use parent's module | name - use the module specified by this name
    *   | valtype     = 0 - XML | 1 - JSON
    *   | start number defines the type (1 - container, 2 - list...)
    *
    *   Metadata and Attributes
    *   | 1) global metadata
    *   |     1.1) glob:last-modified-sec | glob:last-modified-nsec = timestamp (last-modif) [ !!! NOT LOADED ]
    *   |     1.2) glob:candidate-modified = is different from running? (for candidate datastore) [ !!! NOT LOADED ]
    *   |     1.3) glob:perm = owner, group and permissions [ !!! NOT LOADED ]
    *   |    Dataset [ value ]
    *   |
    *   | 2) node metadata and attributes
    *   |     2.1) data:[path]:[module]:[name] = metadata
    *   |    Dataset [ path | name | type | order | value ]
    *   |     2.2) data:[path]:[module]:[name] = attributes
    *   |    Dataset [ path | name | type | order | value ]
    *
    *   [ !!! NOT LOADED ] data are only for internal use
    */

    /* results are limited to one trillion */
    args_array[0] = "FT.AGGREGATE";
    if (asprintf(&arg, "%s:data", mod_ns) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[1] = arg;
    if (xpath_filter) {
        if (asprintf(&arg, "@path:{%s}", xpath_filter) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        args_array[2] = arg;
    } else {
        args_array[2] = "*";
    }
    args_array[3] = "SORTBY";
    args_array[4] = "2";
    args_array[5] = "@order";
    args_array[6] = "ASC";
    args_array[7] = "LOAD";
    args_array[8] = "*";
    args_array[9] = "LIMIT";
    args_array[10] = "0";
    args_array[11] = REDIS_MAX_AGGREGATE_LIMIT;
    args_array[12] = "WITHCURSOR";
    args_array[13] = "COUNT";
    args_array[14] = REDIS_MAX_AGGREGATE_COUNT;

    reply = redisCommandArgv(ctx, argnum, (const char **)args_array, NULL);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
        goto cleanup;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
        goto cleanup;
    }

    while (1) {
        for (i = 1; i < reply->element[0]->elements; ++i) {
            partial = reply->element[0]->element[i];

            /* get order */
            /* we expect to start with order since it is part of the query */
            j = 1;

            /* get path */
            j += 2;
            path = partial->element[j]->str;

            /* get name */
            j += 2;
            name = partial->element[j]->str;

            /* get type */
            j += 2;
            type = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);

            /* get module_name or value based on type */
            switch (type) {
            case SRPDS_DB_LY_CONTAINER: /* container */
            case SRPDS_DB_LY_LIST:      /* list */
            case SRPDS_DB_LY_TERM:      /* leaf or leaf-list */
            case SRPDS_DB_LY_ANY:       /* anydata or anyxml */
            case SRPDS_DB_LY_OPAQUE:    /* opaque node */
                j += 2;
                module_name = partial->element[j]->str;
                break;
            case SRPDS_DB_LY_META:      /* metadata */
            case SRPDS_DB_LY_ATTR:      /* attribute */
                j += 2;
                value = partial->element[j]->str;
                break;
            default:
                break;
            }

            /* get value or keys based on type */
            switch (type) {
            case SRPDS_DB_LY_TERM:      /* leaf or leaf-list */
            case SRPDS_DB_LY_ANY:       /* anydata or anyxml */
            case SRPDS_DB_LY_OPAQUE:    /* opaque node */
                j += 2;
                value = partial->element[j]->str;
                break;
            case SRPDS_DB_LY_LIST:
                j += 2;
                value = partial->element[j]->str;
                if ((err_info = srpds_parse_keys(plugin_name, value, &keys, &lengths))) {
                    goto cleanup;
                }
                break;
            default:
                break;
            }

            /* get default flag based on type */
            switch (type) {
            case SRPDS_DB_LY_TERM:      /* leaf or leaf-list */
            case SRPDS_DB_LY_ANY:       /* anydata or anyxml */
                j += 2;
                dflt_flag = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            default:
                break;
            }

            /* get valtype based on type */
            switch (type) {
            case SRPDS_DB_LY_ANY:       /* anydata or anyxml */
                j += 2;
                valtype = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            default:
                break;
            }

            /* add new node to the data tree */
            if ((err_info = srpds_add_mod_data(plugin_name, mod->ctx, SR_DS_OPERATIONAL, path, name, type, module_name, value, valtype,
                    &dflt_flag, (const char **)keys, lengths, 0, NULL, NULL, &parent_nodes, &pnodes_size,
                    mod_data))) {
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

        reply = redisCommand(ctx, "FT.CURSOR READ %s:data %" PRIu64 " COUNT " REDIS_MAX_AGGREGATE_COUNT, mod_ns, cursor);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
            goto cleanup;
        }
        if (reply->type != REDIS_REPLY_ARRAY) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
            goto cleanup;
        }
    }

    *mod_data = lyd_first_sibling(*mod_data);

cleanup:
    free(keys);
    free(lengths);
    free(parent_nodes);
    free(args_array[1]);
    if (xpath_filter) {
        free(args_array[2]);
    }
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Load all data (only :data) and store them inside the lyd_node structure (for all datastores except oper).
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
srpds_load_conv(redisContext *ctx, const struct lys_module *mod, sr_datastore_t ds, const char *mod_ns, const char *xpath_filter,
        struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    uint64_t valtype = 0, order = 0;
    const char *path, *name, *module_name = NULL, *value = NULL, *path_no_pred = NULL;
    enum srpds_db_ly_types type;
    int dflt_flag = 0;
    char **keys = NULL;
    uint32_t *lengths = NULL;
    srpds_db_userordered_lists_t uo_lists = {0};
    struct lyd_node **parent_nodes = NULL;
    size_t pnodes_size = 0;

    uint32_t i, j;
    redisReply *reply = NULL, *partial = NULL;
    long long cursor;
    int argnum = 25;
    char *args_array[argnum], *arg = NULL;

    /*
    *   Loading multiple different sets of data
    *
    *   Load Conventional Datastore
    *   | 1) containers (LYS_CONTAINER)
    *   |    Dataset [ path | name | type | module_name | path_modif ]
    *   |
    *   | 2) lists (LYS_LIST)
    *   |    Dataset [ path | name | type | module_name | keys | path_modif ]
    *   |
    *   | 3) leafs and leaf-lists (LYS_LEAF and LYS_LEAFLIST)
    *   |    Dataset [ path | name | type | module_name | dflt_flag | value | path_modif ]
    *   |
    *   | 4) anydata and anyxml (LYS_ANYDATA and LYS_ANYXML)
    *   |    Dataset [ path | name | type | module_name | dflt_flag | value | valtype | path_modif ]
    *   |
    *   | 5) user-ordered lists
    *   |    Dataset [ path | name | type | module_name | keys | order | path_no_pred | prev | is_prev_empty | path_modif ]
    *   |
    *   | 6) user-ordered leaf-lists
    *   |    Dataset [ path | name | type | module_name | dflt_flag | value | order | path_no_pred | prev | is_prev_empty | path_modif ]
    *   |
    *   | 7) metadata and maxorder
    *   |
    *   | module_name = "" - use parent's module | name - use the module specified by this name
    *   | valtype     = 0 - XML | 1 - JSON
    *   | start number defines the type (1 - container, 2 - list...)
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

    /* results are limited to one trillion */
    args_array[0] = "FT.AGGREGATE";
    if (asprintf(&arg, "%s:data", mod_ns) == -1) {
        ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
        goto cleanup;
    }
    args_array[1] = arg;
    if (xpath_filter) {
        if (asprintf(&arg, "@path:{%s}", xpath_filter) == -1) {
            ERRINFO(&err_info, plugin_name, SR_ERR_NO_MEMORY, "asprintf()", strerror(errno));
            goto cleanup;
        }
        args_array[2] = arg;
    } else {
        args_array[2] = "*";
    }
    args_array[3] = "SORTBY";
    args_array[4] = "2";
    args_array[5] = "@path_modif";
    args_array[6] = "ASC";
    args_array[7] = "LOAD";
    args_array[8] = "10";
    args_array[9] = "@path";
    args_array[10] = "@name";
    args_array[11] = "@type";
    args_array[12] = "@module_name";
    args_array[13] = "@dflt_flag";
    args_array[14] = "@keys";
    args_array[15] = "@value";
    args_array[16] = "@order";
    args_array[17] = "@valtype";
    args_array[18] = "@path_no_pred";
    args_array[19] = "LIMIT";
    args_array[20] = "0";
    args_array[21] = REDIS_MAX_AGGREGATE_LIMIT;
    args_array[22] = "WITHCURSOR";
    args_array[23] = "COUNT";
    args_array[24] = REDIS_MAX_AGGREGATE_COUNT;

    reply = redisCommandArgv(ctx, argnum, (const char **)args_array, NULL);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
        goto cleanup;
    }
    if (reply->type != REDIS_REPLY_ARRAY) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
        goto cleanup;
    }

    while (1) {
        for (i = 1; i < reply->element[0]->elements; ++i) {
            partial = reply->element[0]->element[i];

            /* get path_modif */
            /* we expect to start with path_modif since it is part of the query */
            j = 1;

            /* get path */
            j += 2;
            path = partial->element[j]->str;

            /* get name */
            j += 2;
            name = partial->element[j]->str;

            /* get type */
            j += 2;
            type = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);

            /* get module_name */
            j += 2;
            module_name = partial->element[j]->str;

            /* get dflt_flag or keys based on type */
            switch (type) {
            case SRPDS_DB_LY_TERM:          /* leaf or leaf-list */
            case SRPDS_DB_LY_ANY:           /* anyxml or anydata */
            case SRPDS_DB_LY_LEAFLIST_UO:   /* user-ordered leaf-list */
                j += 2;
                dflt_flag = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            case SRPDS_DB_LY_LIST:          /* list */
            case SRPDS_DB_LY_LIST_UO:       /* user-ordered list */
                j += 2;
                value = partial->element[j]->str;
                if ((err_info = srpds_parse_keys(plugin_name, value, &keys, &lengths))) {
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
                j += 2;
                value = partial->element[j]->str;
                break;
            case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
                j += 2;
                order = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            default:
                break;
            }

            /* get valtype or path_no_pred or order based on type */
            switch (type) {
            case SRPDS_DB_LY_ANY:  /* anydata and anyxml */
                j += 2;
                valtype = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            case SRPDS_DB_LY_LIST_UO:  /* user-ordered lists */
                j += 2;
                path_no_pred = partial->element[j]->str;
                break;
            case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
                j += 2;
                order = (uint64_t)strtoull(partial->element[j]->str, NULL, 0);
                break;
            default:
                break;
            }

            switch (type) {
            case SRPDS_DB_LY_LEAFLIST_UO:  /* user-ordered leaf-lists */
                j += 2;
                path_no_pred = partial->element[j]->str;
                break;
            default:
                break;
            }

            /* add a new node to mod_data */
            if ((err_info = srpds_add_mod_data(plugin_name, mod->ctx, ds, path, name, type, module_name, value,
                    valtype, &dflt_flag, (const char **)keys, lengths, order, path_no_pred, &uo_lists, &parent_nodes,
                    &pnodes_size, mod_data))) {
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

        reply = redisCommand(ctx, "FT.CURSOR READ %s:data %" PRIu64 " COUNT " REDIS_MAX_AGGREGATE_COUNT, mod_ns, cursor);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", reply->str);
            goto cleanup;
        }
        if (reply->type != REDIS_REPLY_ARRAY) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "FT.AGGREGATE", "No reply array");
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
    free(args_array[1]);
    if (xpath_filter) {
        free(args_array[2]);
    }
    freeReplyObject(reply);
    return err_info;
}

/**
 * @brief Destroy all created indices.
 *
 * @param[in] ctx Redis context.
 * @param[in] mod_ns Database prefix for the module.
 * @param[in] is_oper Whether the indices are destroyed in Operational datastore.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
static sr_error_info_t *
srpds_destroy_indices(redisContext *ctx, char *mod_ns, int is_oper)
{
    sr_error_info_t *err_info = NULL;
    redisReply *reply = NULL;

    /* it is possible to include option DD at the end to delete all associated data as well */
    reply = redisCommand(ctx, "FT.DROPINDEX %s:data DD", mod_ns);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Dropping index", reply->str);
        goto cleanup;
    }

    /* index for maxorder */
    if (!is_oper) {
        freeReplyObject(reply);
        reply = redisCommand(ctx, "FT.DROPINDEX %s:meta DD", mod_ns);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Dropping index", reply->str);
            goto cleanup;
        }
    }
cleanup:
    freeReplyObject(reply);
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
        reply = redisCommand(ctx, "GET %s:perm:owner", mod_ns);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting owner", reply->str);
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
        reply = redisCommand(ctx, "GET %s:perm:group", mod_ns);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting group", reply->str);
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
        reply = redisCommand(ctx, "GET %s:perm:perm", mod_ns);
        if (reply->type == REDIS_REPLY_ERROR) {
            ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting permissions", reply->str);
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
    reply = redisCommand(ctx, "GET %s:glob:candidate-modified", mod_ns);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting candidate-modified flag", reply->str);
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
    if ((err_info = srpds_load_and_del_data(ctx, trg_ds, mod_ns_trg))) {
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
    char *mod_ns = NULL;
    sr_error_info_t *err_info = NULL;
    int modified = 1;
    struct timespec spec = {0};
    uint64_t order = 0;
    struct redis_bulk bulk = {0};

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

    if ((err_info = srpds_bulk_init(0, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, cid, sid, &mod_ns))) {
        goto cleanup;
    }

    if (ds == SR_DS_OPERATIONAL) {
        if ((err_info = srpds_load_and_del_data(ctx, ds, mod_ns))) {
            goto cleanup;
        }
        if ((err_info = srpds_store_oper_recursively(ctx, mod_data, mod_ns, &order, &bulk))) {
            goto cleanup;
        }
    } else if (mod_diff) {
        if ((err_info = srpds_store_diff_recursively(ctx, mod_diff, mod_ns, 0, &bulk))) {
            goto cleanup;
        }
    }
    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

    clock_gettime(CLOCK_REALTIME, &spec);

    /* set flags, e.g. last-modified and/or candidate-modified */
    if ((err_info = srpds_set_flags(ctx, mod_ns, ds, &spec, 1))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    srpds_bulk_destroy(&bulk);
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
    struct redis_bulk bulk = {0};

    assert(mod);

    if ((err_info = srpds_data_init(pdata, &ctx))) {
        goto cleanup;
    }

    if ((err_info = srpds_bulk_init(3, &bulk))) {
        goto cleanup;
    }

    if ((err_info = srpds_get_mod_ns(ds, mod->name, 0, 0, &mod_ns))) {
        goto cleanup;
    }

    /* set the owner */
    /* WARNING!!! Usernames should conform to this regex '^[a-z][_-a-z0-9]*\$',
     * other usernames could cause malfunction of the whole plugin */
    if (owner) {
        if ((err_info = srpds_bulk_start(3, &bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("SET", 3, &bulk);
        if ((err_info = srpds_bulk_add_format(&bulk, "%s:perm:owner", mod_ns))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_add_alloc(owner, strlen(owner), &bulk))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, &bulk))) {
            goto cleanup;
        }
    }

    /* set the group */
    if (group) {
        if ((err_info = srpds_bulk_start(3, &bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("SET", 3, &bulk);
        if ((err_info = srpds_bulk_add_format(&bulk, "%s:perm:group", mod_ns))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_add_alloc(group, strlen(group), &bulk))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, &bulk))) {
            goto cleanup;
        }
    }

    /* set the permissions */
    if (perm) {
        if ((err_info = srpds_bulk_start(3, &bulk))) {
            goto cleanup;
        }
        srpds_bulk_add_const("SET", 3, &bulk);
        if ((err_info = srpds_bulk_add_format(&bulk, "%s:perm:perm", mod_ns))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_add_format(&bulk, "%u", perm))) {
            goto cleanup;
        }
        if ((err_info = srpds_bulk_end(ctx, &bulk))) {
            goto cleanup;
        }
    }

    if ((err_info = srpds_bulk_exec(ctx, &bulk))) {
        goto cleanup;
    }

cleanup:
    free(mod_ns);
    srpds_bulk_destroy(&bulk);
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
    if ((err_info = srpds_redis_access_set(mod, ds, owner ? owner : username, group ? group : groupname, perm, plg_data))) {
        goto cleanup;
    }

    /* create indices for loading - sr_<datastore>:<shm_prefix>:<module>:data and sr_operational:<shm_prefix>:<module>:meta - see load */
    if ((err_info = srpds_create_indices(ctx, mod_ns, (ds == SR_DS_OPERATIONAL)))) {
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
    if ((err_info = srpds_destroy_indices(ctx, mod_ns, (ds == SR_DS_OPERATIONAL)))) {
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

    if ((err_info = srpds_process_load_paths(mod->ctx, xpaths, xpath_count, (ds == SR_DS_OPERATIONAL), &xpath_filter))) {
        goto cleanup;
    }

    if (ds == SR_DS_OPERATIONAL) {
        if ((err_info = srpds_load_oper(ctx, mod, mod_ns, xpath_filter, mod_data))) {
            goto cleanup;
        }
    } else {
        if ((err_info = srpds_load_conv(ctx, mod, ds, mod_ns, xpath_filter, mod_data))) {
            goto cleanup;
        }
    }

cleanup:
    free(xpath_filter);
    free(mod_ns);
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
    reply = redisCommand(ctx, "GET %s:glob:last-modified-sec", mod_ns);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting last-modified flag", reply->str);
        goto cleanup;
    }
    mtime->tv_sec = strtoll(reply->str, NULL, 0);
    freeReplyObject(reply);
    reply = NULL;

    /* get last-modified flag - nanoseconds */
    reply = redisCommand(ctx, "GET %s:glob:last-modified-nsec", mod_ns);
    if (reply->type == REDIS_REPLY_ERROR) {
        ERRINFO(&err_info, plugin_name, SR_ERR_OPERATION_FAILED, "Getting last-modified flag", reply->str);
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
    if ((err_info = srpds_load_and_del_data(ctx, SR_DS_CANDIDATE, mod_ns))) {
        goto cleanup;
    }

    clock_gettime(CLOCK_REALTIME, &spec);

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
    .oper_store_require_diff = 0,
};
