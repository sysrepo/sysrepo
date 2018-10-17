/**
 * @file persistence_manager.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo's Persistence Manager implementation.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <libyang/libyang.h>
#include <sys/types.h>

#include "sr_common.h"
#include "access_control.h"
#include "rp_internal.h"
#include "persistence_manager.h"

#ifdef HAVE_FSETXATTR
#include <sys/xattr.h>
#endif

#define PM_MODULE_NAME "sysrepo-persistent-data"
#define PM_SCHEMA_FILE PM_MODULE_NAME ".yang"  /**< Schema of module's persistent data. */

//! @cond doxygen_suppress
#define PM_XPATH_MODULE                      "/" PM_MODULE_NAME ":module[name='%s']"

#define PM_XPATH_FEATURES                     PM_XPATH_MODULE "/enabled-features/feature-name"
#define PM_XPATH_FEATURES_BY_NAME             PM_XPATH_MODULE "/enabled-features/feature-name[.='%s']"

#define PM_XPATH_SUBSCRIPTION_LIST            PM_XPATH_MODULE "/subscriptions/subscription"

#define PM_XPATH_SUBSCRIPTION                 PM_XPATH_SUBSCRIPTION_LIST "[type='" PM_MODULE_NAME ":%s'][destination-address='%s'][destination-id='%"PRIu32"']"
#define PM_XPATH_SUBSCRIPTION_XPATH           PM_XPATH_SUBSCRIPTION      "/xpath"
#define PM_XPATH_SUBSCRIPTION_USERNAME        PM_XPATH_SUBSCRIPTION      "/username"
#define PM_XPATH_SUBSCRIPTION_EVENT           PM_XPATH_SUBSCRIPTION      "/event"
#define PM_XPATH_SUBSCRIPTION_PRIORITY        PM_XPATH_SUBSCRIPTION      "/priority"
#define PM_XPATH_SUBSCRIPTION_ENABLE_RUNNING  PM_XPATH_SUBSCRIPTION      "/enable-running"
#define PM_XPATH_SUBSCRIPTION_ENABLE_NACM     PM_XPATH_SUBSCRIPTION      "/enable-nacm"
#define PM_XPATH_SUBSCRIPTION_API_VARIANT     PM_XPATH_SUBSCRIPTION      "/api-variant"

#define PM_XPATH_SUBSCRIPTIONS_BY_TYPE        PM_XPATH_SUBSCRIPTION_LIST "[type='" PM_MODULE_NAME ":%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_TYPE_XPATH  PM_XPATH_SUBSCRIPTION_LIST "[type='" PM_MODULE_NAME ":%s'][xpath='%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_DST_ADDR    PM_XPATH_SUBSCRIPTION_LIST "[destination-address='%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_DST_ID      PM_XPATH_SUBSCRIPTION_LIST "[destination-address='%s'][destination-id='%"PRIu32"']"
#define PM_XPATH_SUBSCRIPTIONS_WITH_E_RUNNING PM_XPATH_SUBSCRIPTION_LIST "[enable-running=true()]"
//! @endcond

#define PM_XATTR_NAME "user.write_time" /**< Extended attribute used to store file timestamps. */
#define PM_BILLION 1000000000L          /**< one billion, used for time calculations. */

/**
 * @brief Persistence Manager context.
 */
typedef struct pm_ctx_s {
    rp_ctx_t *rp_ctx;                   /**< Request Processor context. */
    struct ly_ctx *ly_ctx;              /**< libyang context used locally in PM. */
    const struct lys_module *schema;    /**< Schema tree of sysrepo-persistent-data YANG. */
    const char *data_search_dir;        /**< Directory containing the data files. */
    sr_locking_set_t *lock_ctx;         /**< Context for locking persist data files. */
    sr_btree_t *module_data;            /**< Binary tree holding cached data of a module. */
    pthread_rwlock_t module_data_lock;  /**< RW lock for accessing module_data. */
} pm_ctx_t;

/**
 * @brief PM module data info structure.
 */
typedef struct pm_module_data_s {
    const char *module_name;    /**< Name of the module. */
    sr_list_t *cached_data;     /**< Cached data of the module. */
    uint64_t timestamp;         /**< Timestamp of the cached data file. */
    bool use_xattr;             /**< Use file extended attributes to store timestamp. */

} pm_module_data_t;

/**
 * @brief Structure used to store cached data of a module.
 */
typedef struct pm_cached_data_s {
    Sr__SubscriptionType subscription_type;  /**< Type of the subscriptions that are cached in this entry. */
    sr_list_t *subscriptions;                /**< List of the cached subscriptions. */
    bool valid;                              /**< Flag that marks whether the cached data is valid or invalidated. */
} pm_cached_data_t;

/**
 * @brief Compares two module data structures by module name.
 */
static int
pm_module_data_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    pm_module_data_t *data_a = (pm_module_data_t *) a;
    pm_module_data_t *data_b = (pm_module_data_t *) b;

    int res = strcmp(data_a->module_name, data_b->module_name);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up the module data structure.
 */
static void
pm_free_module_data(void *module_data)
{
    pm_module_data_t *md = (pm_module_data_t *) module_data;
    pm_cached_data_t *cd = NULL;

    CHECK_NULL_ARG_VOID(md);

    /* cleanup cached_data */
    for (size_t i = 0; i < md->cached_data->count; i++) {
        cd = md->cached_data->data[i];
        if (cd->valid) {
            np_subscriptions_list_cleanup(cd->subscriptions);
        }
        free(cd);
    }
    sr_list_cleanup(md->cached_data);

    free((void*)md->module_name);
    free(md);
}

/**
 * @brief Saves the data tree into the file specified by file descriptor.
 */
static int
pm_save_data_tree(struct lyd_node *data_tree, int fd)
{
    int ret = 0;

    CHECK_NULL_ARG(data_tree);

    /* empty file content */
    ret = ftruncate(fd, 0);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "File truncate failed: %s", sr_strerror_safe(errno));

    /* print data tree to file */
    ret = lyd_print_fd(fd, data_tree, SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Saving persist data tree failed: %s", ly_errmsg(data_tree->schema->module->ctx));

    /* flush in-core data to the disc */
    ret = fsync(fd);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "File synchronization failed: %s", sr_strerror_safe(errno));

#if defined(HAVE_FSETXATTR) && defined(__linux__)
    /* write precise commit time into the write_time extended attribute */
    struct timespec ts = {0,};
    uint64_t nanotime = 0;
    sr_clock_get_time(CLOCK_MONOTONIC, &ts);
    nanotime = (PM_BILLION * ts.tv_sec) + ts.tv_nsec;
    fsetxattr(fd, PM_XATTR_NAME, &nanotime, sizeof(nanotime), 0);
#endif

    SR_LOG_DBG_MSG("Persist data tree successfully saved.");

    return SR_ERR_OK;
}

/**
 * @brief Cleans up specified data tree and closes specified file descriptor.
 */
static void
pm_cleanup_data_tree(pm_ctx_t *pm_ctx, struct lyd_node *data_tree, int fd)
{
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (-1 != fd && NULL != pm_ctx) {
        sr_locking_set_unlock_close_fd(pm_ctx->lock_ctx, fd);
    }
}

/**
 * @brief Loads the data tree of persistent data file tied to specified YANG module.
 */
static int
pm_load_data_tree(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        bool read_only, struct lyd_node **data_tree, int *fd_p)
{
    char *data_filename = NULL;
    int fd = -1;
    int rc = SR_ERR_OK;
    int error = 0;

    CHECK_NULL_ARG4(pm_ctx, pm_ctx->rp_ctx, module_name, data_tree);

    rc = sr_get_persist_data_file_name(pm_ctx->data_search_dir, module_name, &data_filename);
    CHECK_RC_LOG_RETURN(rc, "Unable to compose persist data file name for '%s'.", module_name);

    /* open the file as the proper user */
    if (NULL != user_cred) {
        ac_set_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
    }

    fd = open(data_filename, O_RDWR);
    error = errno;

    if (NULL != user_cred) {
        ac_unset_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
    }

    if (-1 == fd) {
        /* error by open */
        if (ENOENT == error) {
            SR_LOG_DBG("Persist data file '%s' does not exist.", data_filename);
            if (read_only) {
                SR_LOG_DBG("No persistent data for module '%s' will be loaded.", module_name);
                rc = SR_ERR_DATA_MISSING;
            } else {
                /* create new persist file */
                ac_set_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
                fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                ac_unset_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
                if (-1 == fd) {
                    SR_LOG_ERR("Unable to create new persist data file '%s': %s", data_filename, sr_strerror_safe(error));
                    rc = SR_ERR_INTERNAL;
                }
            }
        } else if (EACCES == error) {
            SR_LOG_ERR("Insufficient permissions to access persist data file '%s'.", data_filename);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SR_LOG_ERR("Unable to open persist data file '%s': %s.", data_filename, sr_strerror_safe(error));
            rc = SR_ERR_INTERNAL;
        }
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* lock & load the data tree */
    rc = sr_locking_set_lock_fd(pm_ctx->lock_ctx, fd, data_filename, (read_only ? false : true), true);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to lock persist data file for '%s'.", module_name);

    ly_errno = LY_SUCCESS;
    *data_tree = sr_lyd_parse_fd(pm_ctx->ly_ctx, fd, SR_FILE_FORMAT_LY, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == *data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing persist data from file '%s' failed: %s", data_filename, ly_errmsg(pm_ctx->ly_ctx));
        rc = SR_ERR_INTERNAL;
    } else {
        SR_LOG_DBG("Persist data successfully loaded from file '%s'.", data_filename);
    }

    if ((SR_ERR_OK != rc) || (true == read_only) || (NULL == fd_p)) {
        /* unlock and close fd in case of read_only has been requested */
        sr_locking_set_unlock_close_fd(pm_ctx->lock_ctx, fd);
    } else {
        /* return open fd to locked file otherwise */
        *fd_p = fd;
    }

cleanup:
    free(data_filename);
    return rc;
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
pm_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    if (LY_LLERR == level) {
        SR_LOG_DBG("libyang error: %s", msg);
    }
}

/**
 * @brief Modifies data tree with persistent data in specified way.
 */
static int
pm_modify_persist_data_tree(pm_ctx_t *pm_ctx, struct lyd_node **data_tree, const char *xpath, const char *value,
        bool add, bool excl, bool *running_affected)
{
    struct lyd_node *node = NULL, *new_node = NULL;
    struct ly_set *node_set = NULL;
    int ret = 0;
    int rc = SR_ERR_OK;

    if (NULL == *data_tree && !add) {
        SR_LOG_DBG("Persist data tree for given module is empty (xpath=%s).", xpath);
        return SR_ERR_DATA_MISSING;
    }

    if (add) {
        /* add persistent data */
        new_node = lyd_new_path(*data_tree, pm_ctx->ly_ctx, xpath, (void*)value, 0, 0);
        if (NULL == *data_tree) {
            /* if the new data tree has been just created */
            *data_tree = new_node;
        }
        if (NULL == new_node) {
            if (LY_EVALID == ly_errno && LYVE_PATH_EXISTS == ly_vecode(pm_ctx->ly_ctx)) {
                if (excl) {
                    SR_LOG_ERR("Persistent data already exist (xpath=%s).", xpath);
                }
                return SR_ERR_DATA_EXISTS;
            } else {
                SR_LOG_ERR("Unable to add new persistent data (xpath=%s): %s.", xpath, ly_errmsg(pm_ctx->ly_ctx));
                return SR_ERR_INTERNAL;
            }
        }
    } else {
        /* delete persistent data */
        node_set = lyd_find_path(*data_tree, xpath);
        if (NULL == node_set || LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Unable to find requested persistent data (xpath=%s): %s.",
                       xpath, ly_errmsg((*data_tree)->schema->module->ctx));
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        if (0 == node_set->number) {
            if (excl) {
                SR_LOG_DBG("Requested persistent data are missing (xpath=%s).", xpath);
            }
            rc = SR_ERR_DATA_MISSING;
            goto cleanup;
        }
        for (size_t i = 0; i < node_set->number; i++) {
            if ((NULL != running_affected) && (false == *running_affected)) {
                /* need to check if running state is affected by delete */
                node = node_set->set.d[i]->child;
                while (NULL != node) {
                    if ((NULL != node->schema->name) && (0 == strcmp(node->schema->name, "enable-running"))) {
                        *running_affected = true;
                        break;
                    }
                    node = node->next;
                }
            }
            ret = lyd_unlink(node_set->set.d[i]);
            if (0 != ret) {
                SR_LOG_ERR("Unable to delete persistent data (xpath=%s): %s.",
                           xpath, ly_errmsg(node_set->set.d[i]->schema->module->ctx));
                rc = SR_ERR_INTERNAL;
                goto cleanup;
            }
            lyd_free(node_set->set.d[i]);
        }
    }

cleanup:
    if (NULL != node_set) {
        ly_set_free(node_set);
    }

    return rc;
}

/**
 * @brief Saves/deletes provided data on provided xpath location within the
 * persistent data file of a module.
 */
static int
pm_save_persistent_data(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const char *xpath, const char *value, bool add, bool excl, struct lyd_node **data_tree_p, bool *running_affected)
{
    struct lyd_node *data_tree = NULL;
    int fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, module_name, xpath);

    if (NULL != running_affected) {
        *running_affected = false;
    }

    if (NULL != data_tree_p && NULL != *data_tree_p) {
        /* use provided data tree */
        data_tree = *data_tree_p;
    } else {
        /* load the data tree from persist file */
        rc = pm_load_data_tree(pm_ctx, user_cred, module_name, false, &data_tree, &fd);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load persist data tree for module '%s'.", module_name);
    }

    rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, add, excl, running_affected);
    if ((add && SR_ERR_DATA_EXISTS == rc) || (!add && SR_ERR_DATA_MISSING == rc)) {
        if (!excl) {
            goto cleanup;
        }
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to modify persist data tree.");

    /* save the changes to the persist file */
    if (-1 != fd) {
        rc = pm_save_data_tree(data_tree, fd);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to save persist data tree.");
    }

    /* if data tree was requested, do not free and return it */
    if (NULL != data_tree_p) {
        *data_tree_p = data_tree;
        data_tree = NULL;
    }

cleanup:
    pm_cleanup_data_tree(pm_ctx, data_tree, fd);
    return rc;
}

/**
 * @brief Fills subscription details from libyang's list instance to subscription structure.
 */
static int
pm_subscription_entry_fill(const char *module_name, np_subscription_t *subscription, struct lyd_node *node)
{
    struct lyd_node_leaf_list *node_ll = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(module_name, subscription, node, node->schema);

    subscription->module_name = strdup(module_name);
    CHECK_NULL_NOMEM_GOTO(subscription->module_name, rc, cleanup);

    while (NULL != node) {
        if (NULL != node->schema && NULL != node->schema->name) {
            node_ll = (struct lyd_node_leaf_list*)node;
            if (0 == strcmp(node->schema->name, "type") && NULL != node_ll->value.ident->name) {
                subscription->type = sr_subsciption_type_str_to_gpb(node_ll->value.ident->name);
            }
            if (0 == strcmp(node->schema->name, "destination-address") && NULL != node_ll->value_str) {
                subscription->dst_address = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(subscription->dst_address, rc, cleanup);
            }
            if (0 == strcmp(node->schema->name, "destination-id") && NULL != node_ll->value_str) {
                subscription->dst_id = atoi(node_ll->value_str);
            }
            if (0 == strcmp(node->schema->name, "xpath") && NULL != node_ll->value_str) {
                subscription->xpath = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(subscription->xpath, rc, cleanup);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "username")) {
                subscription->username = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(subscription->username, rc, cleanup);
            }
            if (0 == strcmp(node->schema->name, "event") && NULL != node_ll->value.ident->name) {
                subscription->notif_event = sr_notification_event_str_to_gpb(node_ll->value.ident->name);
            }
            if (0 == strcmp(node->schema->name, "priority") && NULL != node_ll->value_str) {
                subscription->priority = atoi(node_ll->value_str);
            }
            if (0 == strcmp(node->schema->name, "enable-running")) {
                subscription->enable_running = true;
            }
            if (0 == strcmp(node->schema->name, "enable-nacm")) {
                subscription->enable_nacm = true;
            }
            if (0 == strcmp(node->schema->name, "api-variant") && NULL != node_ll->value_str) {
                subscription->api_variant = sr_api_variant_from_str(node_ll->value_str);
            }
        }
        node = node->next;
    }

    return SR_ERR_OK;

cleanup:
    np_subscription_content_cleanup(subscription);
    memset(subscription, 0, sizeof(*subscription));
    return rc;
}

/**
 * @brief Store persist data file version in the module_data context.
 */
static int
pm_module_data_version_save(pm_ctx_t *pm_ctx, const char *module_name, pm_module_data_t *md)
{
    char file_name[PATH_MAX] = {0,};
    struct stat file_stat = { 0, };
    int ret = 0, rc = SR_ERR_OK;

    rc = sr_get_persist_data_file_name_buf(pm_ctx->data_search_dir, module_name, file_name, PATH_MAX);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to get persist data file name.");

#if defined(HAVE_FSETXATTR) && defined(__linux__)
    /* xattr supported, try to read it */
    ret = getxattr(file_name, PM_XATTR_NAME, &md->timestamp, sizeof(md->timestamp));
    if (0 == ret) {
        md->use_xattr = true;
    } else {
        /* xattr not present/supported, fallback to stat */
        md->use_xattr = false;
    }
#else
    /* xattr not supported */
    md->use_xattr = false;
#endif

    if (!md->use_xattr) {
        /* use stat to determine modification time */
        ret = stat(file_name, &file_stat);
        if (0 == ret) {
#ifdef HAVE_STAT_ST_MTIM
            md->timestamp = (PM_BILLION * file_stat.st_mtim.tv_sec) + file_stat.st_mtim.tv_nsec + file_stat.st_size;
#else
            md->timestamp = file_stat.st_mtime + file_stat.st_size;
#endif
        } else {
            SR_LOG_ERR("Unable to stat file '%s': %s", file_name, sr_strerror_safe(errno));
            rc = SR_ERR_INTERNAL;
        }
    }

cleanup:
    return rc;
}

/**
 * @brief Check whether persist file version changed since storing its data in the module_data context.
 */
static int
pm_module_data_version_changed(pm_ctx_t *pm_ctx, const char *module_name, pm_module_data_t *md, bool *changed)
{
    char file_name[PATH_MAX] = {0,};
    struct stat file_stat = { 0, };
    uint64_t timestamp = 0;
    int ret = 0, rc = SR_ERR_OK;

    *changed = true;

    rc = sr_get_persist_data_file_name_buf(pm_ctx->data_search_dir, module_name, file_name, PATH_MAX);
    CHECK_RC_MSG_RETURN(rc, "Unable to get persist data file name.");

    if (md->use_xattr) {
#if defined(HAVE_FSETXATTR) && defined(__linux__)
        /* use xattr */
        ret = getxattr(file_name, PM_XATTR_NAME, &timestamp, sizeof(timestamp));
        if (0 == ret && timestamp == md->timestamp) {
            SR_LOG_DBG("Module '%s' version matches with cached one(%"PRIu64")", module_name, timestamp);
            *changed = false;
        }
#else
        SR_LOG_ERR_MSG("use_xattr == true, but xattr not supported!");
        return SR_ERR_INTERNAL;
#endif
    } else {
        /* use stat */
        ret = stat(file_name, &file_stat);
        if (0 == ret) {
#ifdef HAVE_STAT_ST_MTIM
            timestamp = (PM_BILLION * file_stat.st_mtim.tv_sec) + file_stat.st_mtim.tv_nsec + file_stat.st_size;
#else
            timestamp = file_stat.st_mtime + file_stat.st_size;
#endif
            if (timestamp == md->timestamp) {
                *changed = false;
            }
        } else {
            SR_LOG_ERR("Unable to stat file '%s': %s", file_name, sr_strerror_safe(errno));
            rc = SR_ERR_INTERNAL;
        }
    }

    if (!(*changed)) {
        SR_LOG_DBG("Module '%s' persist file version matches with cached value (%"PRIu64").", module_name, timestamp);
    } else {
        SR_LOG_DBG("Module '%s' persist file version does not match with the last cached value (%"PRIu64").", module_name, timestamp);
    }

    return rc;
}

/**
 * @brief Invalidates cache of subscriptions of given module.
 */
static int
pm_invalidate_cached_subscriptions(pm_ctx_t *pm_ctx, const char *module_name, Sr__SubscriptionType subscription_type,
        bool all_types)
{
    pm_module_data_t *md = NULL, lookup_md = {0};
    pm_cached_data_t *cd = NULL;

    CHECK_NULL_ARG2(pm_ctx, module_name);

    RWLOCK_WRLOCK_TIMED_CHECK_RETURN(&pm_ctx->module_data_lock);

    /* find module data info */
    lookup_md.module_name = module_name;
    md = sr_btree_search(pm_ctx->module_data, &lookup_md);

    if (NULL == md) {
        /* module data does not exist */
        pthread_rwlock_unlock(&pm_ctx->module_data_lock);
        return SR_ERR_OK;
    }

    /* find cached info of given type */
    for (size_t i = 0; i < md->cached_data->count; i++) {
        cd = md->cached_data->data[i];
        if (cd->valid) {
            if (all_types || (cd->subscription_type == subscription_type)) {
                cd->valid = false;
                np_subscriptions_list_cleanup(cd->subscriptions);
                cd->subscriptions = NULL;
                if (!all_types) {
                    break;
                }
            }
        }
    }

    pthread_rwlock_unlock(&pm_ctx->module_data_lock);

    return SR_ERR_OK;
}

/**
 * @brief Return cached subscriptions of requested module and type, if present in the cache.
 */
static int
pm_get_cached_subscriptions(pm_ctx_t *pm_ctx, const char *module_name, Sr__SubscriptionType subscription_type,
        sr_list_t **subscriptions_p, bool *cache_hit)
{
    pm_module_data_t *md = NULL, lookup_md = {0};
    pm_cached_data_t *cd = NULL, *lookup_cd = NULL;
    sr_list_t *res_subscriptions = NULL;
    np_subscription_t *subscription = NULL;
    bool data_changed = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, module_name, subscriptions_p, cache_hit);

    *cache_hit = false;

    RWLOCK_RDLOCK_TIMED_CHECK_RETURN(&pm_ctx->module_data_lock);

    /* find module data info */
    lookup_md.module_name = module_name;
    md = sr_btree_search(pm_ctx->module_data, &lookup_md);

    if (NULL == md) {
        /* module data does not exist */
        goto cleanup;
    }

    /* check whether data hasn't changed in the meantime */
    rc = pm_module_data_version_changed(pm_ctx, module_name, md, &data_changed);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cached module data version check failed.");

    if (data_changed) {
        /* data has changed */
        goto cleanup;
    }

    /* find cached info of given type */
    for (size_t i = 0; i < md->cached_data->count; i++) {
        lookup_cd = md->cached_data->data[i];
        if (lookup_cd->subscription_type == subscription_type) {
            cd = lookup_cd;
            break;
        }
    }

    if (NULL == cd) {
        /* cached info of given type does not exist */
        goto cleanup;
    }

    if (!cd->valid) {
        /* cache is invalid */
        goto cleanup;
    }

    if (NULL != cd->subscriptions) {
        rc = sr_list_init(&res_subscriptions);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize subscriptions list.");

        for (size_t i = 0; i < cd->subscriptions->count; i++) {
            subscription = cd->subscriptions->data[i];

            rc = sr_list_add(res_subscriptions, subscription);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add a subscription into the subscription list.");

            /* increase copy refcount */
            subscription->copy_cnt += 1;
        }
    }

    *subscriptions_p = res_subscriptions;
    res_subscriptions = NULL;
    *cache_hit = true;

cleanup:
    if (NULL != res_subscriptions) {
        np_subscriptions_list_cleanup(res_subscriptions);
    }
    pthread_rwlock_unlock(&pm_ctx->module_data_lock);

    if (data_changed) {
        pm_invalidate_cached_subscriptions(pm_ctx, module_name, subscription_type, true);
    }

    return rc;
}

/**
 * @brief Store the subscriptions in the cache.
 */
static int
pm_cache_subscriptions(pm_ctx_t *pm_ctx, const char *module_name, Sr__SubscriptionType subscription_type,
        sr_list_t *orig_subscriptions)
{
    pm_module_data_t *md = NULL, *md_tmp = NULL, lookup_md = {0};
    pm_cached_data_t *cd = NULL, *cd_tmp = NULL, *lookup_cd = NULL;
    sr_list_t *cached_subscriptions = NULL;
    np_subscription_t *subscription = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(pm_ctx, module_name);

    RWLOCK_WRLOCK_TIMED_CHECK_RETURN(&pm_ctx->module_data_lock);

    /* find module data info */
    lookup_md.module_name = module_name;
    md = sr_btree_search(pm_ctx->module_data, &lookup_md);

    if (NULL == md) {
        /* module data does not exist, create it */
        md_tmp = calloc(1, sizeof(*md));
        CHECK_NULL_NOMEM_GOTO(md_tmp, rc, cleanup);

        md_tmp->module_name = strdup(module_name);
        CHECK_NULL_NOMEM_GOTO(md_tmp->module_name, rc, cleanup);

        rc = sr_list_init(&md_tmp->cached_data);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Cached data list init failed.");

        rc = sr_btree_insert(pm_ctx->module_data, md_tmp);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Module data btree insert failed.");

        md = md_tmp;
        md_tmp = NULL;
    }

    /* save file version info */
    pm_module_data_version_save(pm_ctx, module_name, md);

    /* find cached info of given type */
    for (size_t i = 0; i < md->cached_data->count; i++) {
        lookup_cd = md->cached_data->data[i];
        if (lookup_cd->subscription_type == subscription_type) {
            cd = lookup_cd;
            break;
        }
    }

    if (NULL == cd) {
        /* cached info of given type does not exist, create it */
        cd_tmp = calloc(1, sizeof(*cd_tmp));
        CHECK_NULL_NOMEM_GOTO(cd_tmp, rc, cleanup);

        cd_tmp->subscription_type = subscription_type;

        rc = sr_list_add(md->cached_data, cd_tmp);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Cached data add failed.");

        cd = cd_tmp;
        cd_tmp = NULL;
    }

    SR_LOG_DBG("Caching %zu subscriptions from '%s' persist file.",
            (NULL != orig_subscriptions) ? orig_subscriptions->count : 0, module_name);

    /* fill in the list of pointers to subscriptions & store it in the cache */
    if (NULL != orig_subscriptions) {
        rc = sr_list_init(&cached_subscriptions);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize cached subscriptions list.");

        for (size_t i = 0; i < orig_subscriptions->count; i++) {
            subscription = orig_subscriptions->data[i];

            rc = sr_list_add(cached_subscriptions, subscription);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add a subscription into the cache list.");

            /* increase copy refcount */
            subscription->copy_cnt += 1;
        }
    }

    cd->valid = true;
    cd->subscriptions = cached_subscriptions;
    cached_subscriptions = NULL;

cleanup:
    if (NULL != cached_subscriptions) {
        np_subscriptions_list_cleanup(cached_subscriptions);
    }
    if (NULL != md_tmp) {
        sr_list_cleanup(md_tmp->cached_data);
        free((void*)md_tmp->module_name);
        free(md_tmp);
    }
    if (NULL != cd_tmp) {
        free(cd_tmp);
    }
    pthread_rwlock_unlock(&pm_ctx->module_data_lock);

    return rc;
}

/**
 * @brief Checks whether there are some subscriptions that enable running datastore
 * within the data tree.
 */
static int
pm_dt_has_running_enable_susbscriptions(struct lyd_node *data_tree, const char *module_name, bool *result)
{
    char xpath[PATH_MAX] = { 0, };
    struct ly_set *node_set = NULL;

    CHECK_NULL_ARG3(data_tree, module_name, result);

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_WITH_E_RUNNING, module_name);
    node_set = lyd_find_path(data_tree, xpath);
    if (NULL == node_set || 0 == node_set->number) {
        *result = false;
    } else {
        *result = true;
    }

    if (NULL != node_set) {
        ly_set_free(node_set);
    }

    return SR_ERR_OK;
}

int
pm_init(rp_ctx_t *rp_ctx, const char *schema_search_dir, const char *data_search_dir, pm_ctx_t **pm_ctx)
{
    pm_ctx_t *ctx = NULL;
    char *schema_filename = NULL;
    pthread_rwlockattr_t attr;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(rp_ctx, schema_search_dir, data_search_dir, pm_ctx);

    /* allocate and initialize the context */
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_GOTO(ctx, rc, cleanup);

    ctx->rp_ctx = rp_ctx;
    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    rc = sr_locking_set_init(&ctx->lock_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize locking set.");

    pthread_rwlockattr_init(&attr);
#if defined(HAVE_PTHREAD_RWLOCKATTR_SETKIND_NP)
    pthread_rwlockattr_setkind_np(&attr, PTHREAD_RWLOCK_PREFER_WRITER_NONRECURSIVE_NP);
#endif

    rc = pthread_rwlock_init(&ctx->module_data_lock, &attr);
    CHECK_ZERO_MSG_GOTO(rc, rc, SR_ERR_INTERNAL, cleanup, "lyctx mutex initialization failed");

    rc = sr_btree_init(pm_module_data_cmp, pm_free_module_data, &ctx->module_data);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Module data binary tree init failed.");

    /* initialize libyang */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir, 0);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR_MSG("libyang initialization failed");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }

    ly_set_log_clb(pm_ly_log_cb, 0);

    rc = sr_str_join(schema_search_dir, PM_SCHEMA_FILE, &schema_filename);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* load persist files schema to context */
    ctx->schema = lys_parse_path(ctx->ly_ctx, schema_filename, LYS_IN_YANG);
    free(schema_filename);
    if (NULL == ctx->schema) {
        SR_LOG_ERR("Unable to parse the schema file '%s': %s", PM_SCHEMA_FILE, ly_errmsg(ctx->ly_ctx));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    *pm_ctx = ctx;

cleanup:
    pthread_rwlockattr_destroy(&attr);
    if (SR_ERR_OK != rc) {
        pm_cleanup(ctx);
    }
    return rc;
}

void
pm_cleanup(pm_ctx_t *pm_ctx)
{
    if (NULL != pm_ctx) {
        if (NULL != pm_ctx->ly_ctx) {
            ly_ctx_destroy(pm_ctx->ly_ctx, NULL);
        }
        pthread_rwlock_destroy(&pm_ctx->module_data_lock);
        sr_btree_cleanup(pm_ctx->module_data);
        sr_locking_set_cleanup(pm_ctx->lock_ctx);
        free((void*)pm_ctx->data_search_dir);
        free(pm_ctx);
    }
}

int
pm_save_feature_state(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const char *feature_name, bool enable)
{
    char xpath[PATH_MAX] = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, user_cred, module_name, feature_name);

    if (enable) {
        /* enable the feature */
        snprintf(xpath, PATH_MAX, PM_XPATH_FEATURES, module_name);

        rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, feature_name, true, false, NULL, NULL);

        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Feature '%s' successfully enabled in '%s' persist data tree.", feature_name, module_name);
        }
    } else {
        /* disable the feature */
        snprintf(xpath, PATH_MAX, PM_XPATH_FEATURES_BY_NAME, module_name, feature_name);

        rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, NULL, false, false, NULL, NULL);

        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Feature '%s' successfully disabled in '%s' persist file.", feature_name, module_name);
        }
    }

    return rc;
}

int
pm_get_module_info(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name, sr_mem_ctx_t *sr_mem_features,
        bool *module_enabled, char ***subtrees_enabled_p, size_t *subtrees_enabled_cnt_p, char ***features_p,
        size_t *features_cnt_p)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    struct ly_set *node_set = NULL;
    char **subtrees_enabled = NULL, **features = NULL, **tmp = NULL;
    const char *feature_name = NULL;
    size_t subtrees_enabled_cnt = 0, feature_cnt = 0;
    np_subscription_t subscription = { 0, };
    sr_mem_snapshot_t snapshot = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, module_name, module_enabled);
    CHECK_NULL_ARG4(subtrees_enabled_p, subtrees_enabled_cnt_p, features_p, features_cnt_p);

    *module_enabled = false;
    *subtrees_enabled_p = NULL;
    *subtrees_enabled_cnt_p = 0;
    *features_p = NULL;
    *features_cnt_p = 0;

    if (sr_mem_features) {
        sr_mem_snapshot(sr_mem_features, &snapshot);
    }

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, user_cred, module_name, true, &data_tree, NULL);
    if (SR_ERR_DATA_MISSING != rc) {
        /* ignore data missing error */
        CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load persist data tree for module '%s'.", module_name);
    }

    if (NULL == data_tree) {
        /* empty data file */
        goto cleanup;
    }

    /* get all enabled features */
    snprintf(xpath, PATH_MAX, PM_XPATH_FEATURES, module_name);
    node_set = lyd_find_path(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        features = sr_calloc(sr_mem_features, node_set->number, sizeof(*features));
        CHECK_NULL_NOMEM_GOTO(features, rc, cleanup);

        for (size_t i = 0; i < node_set->number; i++) {
            feature_name = ((struct lyd_node_leaf_list *)node_set->set.d[i])->value_str;
            if (NULL != feature_name) {
                sr_mem_edit_string(sr_mem_features, &features[feature_cnt], feature_name);
                CHECK_NULL_NOMEM_GOTO(features[feature_cnt], rc, cleanup);
                feature_cnt++;
            }
        }
    }
    if (NULL != node_set) {
        ly_set_free(node_set);
    }

    /* get all subscriptions that enable running */
    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_WITH_E_RUNNING, module_name);
    node_set = lyd_find_path(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        for (size_t i = 0; i < node_set->number; i++) {
            memset(&subscription, 0, sizeof(subscription));
            rc = pm_subscription_entry_fill(module_name, &subscription, node_set->set.d[i]->child);
            if (SR_ERR_OK == rc) {
                if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription.type) {
                    *module_enabled = true;
                }
                if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription.type ||
                        SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == subscription.type) {
                    tmp = realloc(subtrees_enabled, (subtrees_enabled_cnt + 1) * sizeof(*subtrees_enabled));
                    CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
                    subtrees_enabled = tmp;
                    subtrees_enabled[subtrees_enabled_cnt] = strdup(subscription.xpath);
                    CHECK_NULL_NOMEM_GOTO(subtrees_enabled[subtrees_enabled_cnt], rc, cleanup);
                    subtrees_enabled_cnt++;
                }
            }
            if (SR_ERR_OK == rc) {
                /* send HELLO notifications to verify that these subscriptions are still alive */
                rc = np_hello_notify(pm_ctx->rp_ctx->np_ctx, module_name, subscription.dst_address, subscription.dst_id);
            }
            np_subscription_content_cleanup(&subscription);
        }
    }

    SR_LOG_DBG("Returning info from '%s' persist file: module %s, %zu subtrees enabled in running, %zu features enabled.",
            module_name, (*module_enabled ? "enabled" : "disabled"), subtrees_enabled_cnt, feature_cnt);

    *subtrees_enabled_p = subtrees_enabled;
    *subtrees_enabled_cnt_p = subtrees_enabled_cnt;
    *features_p = features;
    *features_cnt_p = feature_cnt;

cleanup:
    if (NULL != node_set) {
        ly_set_free(node_set);
    }
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }

    if (SR_ERR_OK != rc) {
        for (size_t i = 0; i < subtrees_enabled_cnt; i++) {
            free((void*)subtrees_enabled[i]);
        }
        free(subtrees_enabled);
        if (sr_mem_features) {
            sr_mem_restore(&snapshot);
        } else {
            for (size_t i = 0; i < feature_cnt; i++) {
                free((void*)features[i]);
            }
            free(features);
        }
    }
    return rc;
}

int
pm_add_subscription(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const np_subscription_t *subscription, const bool exclusive)
{
    char xpath[PATH_MAX] = { 0, }, buff[15] = { 0, }, *tmp_xpath = NULL, *ptr;
    const char *value = NULL;
    struct lyd_node *data_tree = NULL;
    int fd = -1;
    int rc = SR_ERR_OK;

    rc = pm_load_data_tree(pm_ctx, user_cred, module_name, false, &data_tree, &fd);
    CHECK_RC_LOG_RETURN(rc, "Unable to load persist data tree for module '%s'.", module_name);

    if (exclusive) {
        /* first, delete existing subscriptions of given type */
        SR_LOG_DBG("Removing all existing %s subscriptions from '%s' persist data tree.",
                sr_subscription_type_gpb_to_str(subscription->type), module_name);

        if (subscription->xpath) {
            /* make sure there will be no illegal quotes */
            if (strchr(subscription->xpath, '\'')) {
                tmp_xpath = strdup(subscription->xpath);
                for (ptr = strchr(tmp_xpath, '\''); ptr; ptr = strchr(ptr + 1, '\'')) {
                    *ptr = '"';
                }
            }
        } else {
            tmp_xpath = malloc(1 + strlen(module_name) + 6);
            sprintf(tmp_xpath, "/%s:*//.", module_name);
        }

        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_TYPE_XPATH, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), tmp_xpath ? tmp_xpath : subscription->xpath);
        free(tmp_xpath);

        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, NULL, false, true, NULL);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Unable to delete existing %s subscriptions.", sr_subscription_type_gpb_to_str(subscription->type));
        }
    }

    /* create the subscription */
    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION, module_name,
            sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
    rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, NULL, true, true, NULL);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new subscription into the data tree.");

    /* set subscription details */
    if (subscription->enable_running && (
            SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == subscription->type)) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_ENABLE_RUNNING, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, NULL, true, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (NULL != subscription->xpath) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_XPATH, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        value = subscription->xpath;
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == subscription->type) {
        if (NULL != subscription->username) {
            snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_USERNAME, module_name,
                    sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
            value = subscription->username;
            rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, true, NULL);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
        }
        if (subscription->enable_nacm) {
            snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_ENABLE_NACM, module_name,
                     sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
            rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, NULL, true, true, NULL);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
        }
    }
    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_EVENT, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        value = sr_notification_event_gpb_to_str(subscription->notif_event);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_PRIORITY, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        snprintf(buff, sizeof(buff), "%"PRIu32, subscription->priority);
        value = buff;
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (SR__SUBSCRIPTION_TYPE__RPC_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__ACTION_SUBS == subscription->type) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_API_VARIANT, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        value = sr_api_variant_to_str(subscription->api_variant);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }

    rc = pm_save_data_tree(data_tree, fd);

    if (SR_ERR_OK == rc) {
        if (subscription->xpath) {
            SR_LOG_DBG("Subscription entry '%s' successfully added into '%s' persist data tree.", subscription->xpath, module_name);
        } else {
            SR_LOG_DBG("All module notifications subscription entry successfully added into '%s' persist data tree.", module_name);
        }
    }

cleanup:
    pm_cleanup_data_tree(pm_ctx, data_tree, fd);
    return rc;
}

int
pm_remove_subscription(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const np_subscription_t *subscription, bool *disable_running)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    bool running_affected = false, has_running_enable_susbscriptions = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(pm_ctx, user_cred, module_name, subscription, disable_running);

    /* invalidate the subscription cache for this module and subscription type */
    pm_invalidate_cached_subscriptions(pm_ctx, module_name, subscription->type, false);

    *disable_running = false;

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION, module_name,
            sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);

    rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, NULL, false, true, &data_tree, &running_affected);
    if (NULL != data_tree) {
        if (running_affected) {
            /* check if some subscriptions that enable running left */
            rc = pm_dt_has_running_enable_susbscriptions(data_tree, module_name, &has_running_enable_susbscriptions);
            if (SR_ERR_OK == rc && !has_running_enable_susbscriptions) {
                *disable_running = true;
            }
        }
        lyd_free_withsiblings(data_tree);
    }

    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("Subscription entry successfully removed from '%s' persist file.", module_name);
    }

    return rc;
}

int
pm_remove_subscriptions_for_destination(pm_ctx_t *pm_ctx, const char *module_name, const char *dst_address,
        bool *disable_running)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    bool running_affected = false, has_running_enable_susbscriptions = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, module_name, dst_address, disable_running);

    /* invalidate the subscription cache for this module */
    pm_invalidate_cached_subscriptions(pm_ctx, module_name, 0, true);

    *disable_running = false;

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_DST_ADDR, module_name, dst_address);

    /* remove the subscriptions */
    rc = pm_save_persistent_data(pm_ctx, NULL, module_name, xpath, NULL, false, true, &data_tree, &running_affected);
    if (NULL != data_tree) {
        /* check if some subscriptions that enable running left */
        if (running_affected) {
            /* check if some subscriptions that enable running left */
            rc = pm_dt_has_running_enable_susbscriptions(data_tree, module_name, &has_running_enable_susbscriptions);
            if (SR_ERR_OK == rc && !has_running_enable_susbscriptions) {
                *disable_running = true;
            }
        }
        lyd_free_withsiblings(data_tree);
    }

    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("Subscription entries for destination '%s' successfully removed from '%s' persist file.",
                dst_address, module_name);
    }

    return rc;
}

int
pm_get_subscriptions(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name, Sr__SubscriptionType type,
        sr_list_t **subscriptions_p)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    struct ly_set *node_set = NULL;
    sr_list_t *subscriptions_list = NULL;
    np_subscription_t *subscription = NULL;
    bool cache_hit = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, module_name, subscriptions_p);

    /* attempt to satisfy the request from cache */
    rc = pm_get_cached_subscriptions(pm_ctx, module_name, type, subscriptions_p, &cache_hit);
    if (cache_hit) {
        SR_LOG_DBG("Returning %zu subscriptions from '%s' persist file cache.",
                (NULL != *subscriptions_p) ? (*subscriptions_p)->count : 0, module_name);
        return rc;
    }

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, user_cred, module_name, true, &data_tree, NULL);
    if (SR_ERR_DATA_MISSING != rc) {
        CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load persist data tree for module '%s' %s.", module_name, sr_strerror(rc));
    }

    if (NULL == data_tree) {
        /* empty data file */
        *subscriptions_p = NULL;
        rc = SR_ERR_OK;
        goto cleanup;
    }

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_TYPE, module_name, sr_subscription_type_gpb_to_str(type));
    node_set = lyd_find_path(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        rc = sr_list_init(&subscriptions_list);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to init subscription list.");

        for (size_t i = 0; i < node_set->number; i++) {
            subscription = calloc(1, sizeof(*subscription));
            CHECK_NULL_NOMEM_GOTO(subscription, rc, cleanup);

            rc = pm_subscription_entry_fill(module_name, subscription, node_set->set.d[i]->child);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to fill subscription details.");

            rc = sr_list_add(subscriptions_list, subscription);
            subscription = NULL;
        }
    }

    /* store the result in the cache */
    pm_cache_subscriptions(pm_ctx, module_name, type, subscriptions_list);

    SR_LOG_DBG("Returning %zu subscriptions found in '%s' persist file.",
            (NULL == subscriptions_list ? 0 : subscriptions_list->count), module_name);

    *subscriptions_p = subscriptions_list;

cleanup:
    if (NULL != node_set) {
        ly_set_free(node_set);
    }
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }

    if (SR_ERR_OK != rc) {
        np_subscriptions_list_cleanup(subscriptions_list);
        np_subscription_cleanup(subscription);
    }

    return rc;
}
