/**
 * @file notification_processor.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Notification Processor implementation.
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
#include <stdio.h>
#include <inttypes.h>
#include <pthread.h>
#include <fcntl.h>
#include <dirent.h>
#include <math.h>
#include <time.h>

#include "sr_common.h"
#include "rp_internal.h"
#include "persistence_manager.h"
#include "notification_processor.h"
#include "request_processor.h"
#include "data_manager.h"

#define NP_NS_SCHEMA_FILE                  "sysrepo-notification-store.yang"  /**< Schema of notification store. */
#define NP_NS_XPATH_NOTIFICATION           "/sysrepo-notification-store:notifications/notification[xpath='%s'][generated-time='%s'][logged-time='%u']"  /**< XPath of one notification entry */
#define NP_NS_XPATH_NOTIFICATION_BY_XPATH  "/sysrepo-notification-store:notifications/notification[xpath='%s']" /**< XPath of notification entry identified only by xpath */

/**
 * @brief Information about a notification destination.
 */
typedef struct np_dst_info_s {
    const char *dst_address;        /**< Destination address. */
    char **subscribed_modules;      /**< Array of module names which the destination has subscriptions for. */
    size_t subscribed_modules_cnt;  /**< Number of the modules with subscriptions. */
} np_dst_info_t;

/**
 * @brief Context holding information about notifications sent per commit.
 */
typedef struct np_commit_ctx_s {
    uint32_t commit_id;              /**< Commit identifier. */
    bool all_notifications_sent;     /**< Flag indicating whether all commit notifications has been already sent. */
    bool commit_finished;            /**< TRUE if commit has finished and can be released, FALSE if it will continue with another phase. */
    size_t notifications_sent;       /**< Count of sent notifications. */
    size_t notifications_acked;      /**< Count of received acknowledgments. */
    int result;                      /**< Used to store overall result of the commit operation. */
    sr_list_t *err_subs_xpaths;      /**< Used to store xpaths to subscribers that returned an error. */
    sr_list_t *errors;               /**< Used to store errors returned from commit verifiers. */
} np_commit_ctx_t;

/**
 * @brief Notification Processor context.
 */
typedef struct np_ctx_s {
    rp_ctx_t *rp_ctx;                     /**< Request Processor context. */
    np_subscription_t **subscriptions;    /**< List of active non-persistent subscriptions. */
    size_t subscription_cnt;              /**< Number of active non-persistent subscriptions. */
    sr_btree_t *dst_info_btree;           /**< Binary tree used for fast destination info lookup. */
    sr_llist_t *commits;                  /**< Linked-list of ongoing commits. */
    pthread_rwlock_t lock;                /**< Read-write lock for the context. */
    struct ly_ctx *ly_ctx;                /**< libyang context used locally in NP. */
    const char *data_search_dir;          /**< Directory containing the data files. */
    const struct lys_module *ns_schema;   /**< Schema tree of the notification store YANG. */
    sr_locking_set_t *lock_ctx;           /**< Context for locking notification store files. */
    bool do_notif_store_cleanup;          /**< TRUE if notification store cleanups should be performed.*/
} np_ctx_t;

/**
 * @brief Compares two notification destination information structures by
 * associated destination addresses (used by lookups in binary tree).
 */
static int
np_dst_info_cmp(const void *a, const void *b)
{
    assert(a);
    assert(b);
    np_dst_info_t *dst_info_a = (np_dst_info_t*)a;
    np_dst_info_t *dst_info_b = (np_dst_info_t*)b;

    int res = 0;

    assert(dst_info_a->dst_address);
    assert(dst_info_b->dst_address);

    res = strcmp(dst_info_a->dst_address, dst_info_b->dst_address);
    if (0 == res) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }
}

/**
 * @brief Cleans up a notification destination information structure.
 * @note Called automatically when a node from the binary tree is removed
 * (which is also when the tree itself is being destroyed).
 */
static void
np_dst_info_cleanup(void *dst_info_p)
{
    np_dst_info_t *dst_info = NULL;

    if (NULL != dst_info_p) {
        dst_info = (np_dst_info_t *)dst_info_p;
        for (size_t i = 0; i < dst_info->subscribed_modules_cnt; i++) {
            free(dst_info->subscribed_modules[i]);
        }
        free(dst_info->subscribed_modules);
        free((void*)dst_info->dst_address);
        free(dst_info);
    }
}

/**
 * @brief Adds information about notification destination into NP context.
 */
static int
np_dst_info_insert(np_ctx_t *np_ctx, const char *dst_address, const char *module_name)
{
    np_dst_info_t info_lookup = { 0, }, *info = NULL, *new_info = NULL;
    char **tmp = NULL;
    bool inserted = false;
    int rc = SR_ERR_OK;
    int rdlock_result = 0;
    int wrlock_result = 0;

    CHECK_NULL_ARG3(np_ctx, dst_address, module_name);

    rdlock_result = pthread_rwlock_rdlock(&np_ctx->lock);

    /* find info entry matching with the destination */
    info_lookup.dst_address = dst_address;
    info = sr_btree_search(np_ctx->dst_info_btree, &info_lookup);

    if (NULL != info) {
        /* info entry found */
        for (size_t i = 0; i < info->subscribed_modules_cnt; i++) {
            if (0 == strcmp(info->subscribed_modules[i], module_name)) {
                /* module name already exists within the info entry, no update needed */
                if (0 == rdlock_result) {
                    pthread_rwlock_unlock(&np_ctx->lock);
                }
                return SR_ERR_OK;
            }
        }
    }

    /* info update is required */
    if (0 == rdlock_result) {
        pthread_rwlock_unlock(&np_ctx->lock);
    }
    wrlock_result = pthread_rwlock_wrlock(&np_ctx->lock);

    if (NULL == info) {
        /* info entry not found, create new one */
        new_info = calloc(1, sizeof(*new_info));
        CHECK_NULL_NOMEM_GOTO(new_info, rc, cleanup);

        new_info->dst_address = strdup(dst_address);
        CHECK_NULL_NOMEM_GOTO(new_info->dst_address, rc, cleanup);

        rc = sr_btree_insert(np_ctx->dst_info_btree, new_info);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to insert new info entry into btree.");
        inserted = true;
        info = new_info;
    }

    /* add the module into info entry */
    tmp = realloc(info->subscribed_modules, (info->subscribed_modules_cnt + 1) * sizeof(*tmp));
    CHECK_NULL_NOMEM_GOTO(tmp, rc, cleanup);
    info->subscribed_modules = tmp;

    info->subscribed_modules[info->subscribed_modules_cnt] = strdup(module_name);
    CHECK_NULL_NOMEM_GOTO(info->subscribed_modules[info->subscribed_modules_cnt], rc, cleanup);
    info->subscribed_modules_cnt++;

    if (0 == wrlock_result) {
        pthread_rwlock_unlock(&np_ctx->lock);
    }
    return SR_ERR_OK;

cleanup:
    if (NULL != new_info) {
        if (inserted) {
            sr_btree_delete(np_ctx->dst_info_btree, new_info);
        } else {
            free((char*)new_info->dst_address);
            free((char*)new_info->subscribed_modules);
            free(new_info);
        }
    }
    if (0 == wrlock_result) {
        pthread_rwlock_unlock(&np_ctx->lock);
    }
    return rc;
}

/**
 * @brief Removes information about notification destination from NP context.
 */
static int
np_dst_info_remove(np_ctx_t *np_ctx, const char *dst_address, const char *module_name)
{
    np_dst_info_t info_lookup = { 0, }, *info = NULL;

    CHECK_NULL_ARG2(np_ctx, dst_address);

    info_lookup.dst_address = dst_address;

    /* find specified module name */
    info = sr_btree_search(np_ctx->dst_info_btree, &info_lookup);
    if (NULL != info) {
        if (NULL == module_name || 1 == info->subscribed_modules_cnt) {
            /* if whole destination info entry needs to be removed OR this is the last module,
             * remove whole destination info entry */
            sr_btree_delete(np_ctx->dst_info_btree, info);
        } else {
            /* not last module - remove only the matching module name */
            for (size_t i = 0; i < info->subscribed_modules_cnt; i++) {
                if (0 == strcmp(info->subscribed_modules[i], module_name)) {
                    /* remove this module from info entry */
                    free((void*)info->subscribed_modules[i]);
                    if (i < (info->subscribed_modules_cnt - 1)) {
                        memmove(info->subscribed_modules + i,
                                info->subscribed_modules + i + 1,
                                (info->subscribed_modules_cnt - i - 1) * sizeof(*info->subscribed_modules));
                    }
                    info->subscribed_modules_cnt--;
                    break;
                }
            }
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Find commit context in the NP context by provided commit ID.
 */
static np_commit_ctx_t *
np_commit_ctx_find(np_ctx_t *np_ctx, uint32_t commit_id, sr_llist_node_t **llist_node)
{
    sr_llist_node_t *node = NULL;
    np_commit_ctx_t *commit = NULL;
    bool matched = false;

    if ((NULL != np_ctx) && (NULL != np_ctx->commits)) {
        node = np_ctx->commits->first;
        while (NULL != node) {
            commit = (np_commit_ctx_t*)node->data;
            if ((NULL != commit) && (commit->commit_id == commit_id)) {
                matched = true;
                break;
            }
            node = node->next;
        }
    }

    if (matched) {
        if (NULL != llist_node) {
            *llist_node = node;
        }
        return commit;
    } else {
        return NULL;
    }
}

/**
 * @brief Create a commit for the specified commit ID.
 */
static np_commit_ctx_t *
np_commit_create(np_ctx_t *np_ctx, uint32_t commit_id)
{
    np_commit_ctx_t *commit = NULL;

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, NULL);

    if (NULL == commit) {
        /* add a new commit context */
        SR_LOG_DBG("Creating a new NP commit context for commit ID %"PRIu32".", commit_id);

        commit = calloc(1, sizeof(*commit));
        if (!commit) {
            goto unlock;
        }

        commit->commit_id = commit_id;
        sr_llist_add_new(np_ctx->commits, commit);
    }

unlock:
    pthread_rwlock_unlock(&np_ctx->lock);

    return commit;
}

/**
 * @brief Adds an error xpath into commit context.
 */
static int
np_commit_error_add(np_commit_ctx_t *commit_ctx, const char *err_subs_xpath, bool do_not_send_abort,
        const char *err_msg, const char *err_xpath)
{
    sr_error_info_t *error = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(commit_ctx, err_subs_xpath);

    if (do_not_send_abort) {
        SR_LOG_DBG("Subscription '%s' doesn't want abort notification", err_subs_xpath);
        if (NULL == commit_ctx->err_subs_xpaths) {
            rc = sr_list_init(&commit_ctx->err_subs_xpaths);
            CHECK_RC_MSG_RETURN(rc, "Unable to init sr_list for errored verifier xpaths.");
        }
        rc = sr_list_add(commit_ctx->err_subs_xpaths, strdup(err_subs_xpath));
    }
    if (SR_ERR_OK == rc && NULL != err_msg) {
        if (NULL == commit_ctx->errors) {
            rc = sr_list_init(&commit_ctx->errors);
        }
        if (SR_ERR_OK == rc) {
            error = calloc(1, sizeof(*error));
            error->message = strdup(err_msg);
            if (NULL != err_xpath) {
                error->xpath = strdup(err_xpath);
            }
            rc = sr_list_add(commit_ctx->errors, error);
        }
    }

    return rc;
}

/**
 * @brief Loads the data tree from provided file.
 */
static int
np_load_data_tree(np_ctx_t *np_ctx, const ac_ucred_t *user_cred, const char *data_filename,
        const bool read_only, struct lyd_node **data_tree, int *fd_p)
{
    int fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, np_ctx->rp_ctx, data_filename, data_tree);

    /* open the file as the proper user */
    if (NULL != user_cred) {
        ac_set_user_identity(np_ctx->rp_ctx->ac_ctx, user_cred);
    }

    fd = open(data_filename, O_RDWR);

    if (NULL != user_cred) {
        ac_unset_user_identity(np_ctx->rp_ctx->ac_ctx, user_cred);
    }

    if (-1 == fd) {
        /* error by open */
        if (ENOENT == errno) {
            SR_LOG_DBG("Data file '%s' does not exist.", data_filename);
            if (read_only) {
                SR_LOG_DBG("No data for '%s' will be loaded.", data_filename);
                rc = SR_ERR_DATA_MISSING;
            } else {
                /* create new persist file */
                ac_set_user_identity(np_ctx->rp_ctx->ac_ctx, user_cred);
                fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                ac_unset_user_identity(np_ctx->rp_ctx->ac_ctx, user_cred);
                if (-1 == fd) {
                    SR_LOG_ERR("Unable to create a new data file '%s': %s", data_filename, sr_strerror_safe(errno));
                    rc = SR_ERR_INTERNAL;
                }
            }
        } else if (EACCES == errno) {
            SR_LOG_ERR("Insufficient permissions to access the data file '%s'.", data_filename);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SR_LOG_ERR("Unable to open the data file '%s': %s.", data_filename, sr_strerror_safe(errno));
            rc = SR_ERR_INTERNAL;
        }
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
    }

    /* lock & load the data tree */
    rc = sr_locking_set_lock_fd(np_ctx->lock_ctx, fd, data_filename, (read_only ? false : true), true);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to lock data file '%s'.", data_filename);

    ly_errno = LY_SUCCESS;
    *data_tree = sr_lyd_parse_fd(np_ctx->ly_ctx, fd, SR_FILE_FORMAT_LY, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == *data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing data from file '%s' failed: %s", data_filename, ly_errmsg(np_ctx->ly_ctx));
        rc = SR_ERR_INTERNAL;
    } else {
        SR_LOG_DBG("Data successfully loaded from file '%s'.", data_filename);
    }

    if ((SR_ERR_OK != rc) || (true == read_only) || (NULL == fd_p)) {
        /* unlock and close fd in case of read_only has been requested */
        sr_locking_set_unlock_close_fd(np_ctx->lock_ctx, fd);
    } else {
        /* return open fd to locked file otherwise */
        *fd_p = fd;
    }

cleanup:
    return rc;
}

/**
 * @brief Saves the data tree into the file specified by file descriptor.
 */
static int
np_save_data_tree(struct lyd_node *data_tree, int fd)
{
    int ret = 0;

    CHECK_NULL_ARG(data_tree);

    /* empty file content */
    ret = ftruncate(fd, 0);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "File truncate failed: %s", sr_strerror_safe(errno));

    /* print data tree to file */
    ret = lyd_print_fd(fd, data_tree, SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT | LYP_WD_EXPLICIT);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Saving notification store data tree failed: %s",
                          ly_errmsg(data_tree->schema->module->ctx));

    /* flush in-core data to the disc */
    ret = fsync(fd);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "File synchronization failed: %s", sr_strerror_safe(errno));

    SR_LOG_DBG_MSG("Data tree successfully saved.");

    return SR_ERR_OK;
}

/**
 * @brief Cleans up specified data tree and closes specified file descriptor.
 */
static void
np_cleanup_data_tree(np_ctx_t *np_ctx, struct lyd_node *data_tree, int fd)
{
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }
    if (-1 != fd && NULL != np_ctx) {
        sr_locking_set_unlock_close_fd(np_ctx->lock_ctx, fd);
    }
}

/**
 * @brief Returns the name of a file that can be used to store a notification received in given time.
 */
static int
np_get_notif_store_filename(const char *module_name, time_t received_time, char *filename_buff, size_t filename_buff_size)
{
    mode_t old_umask = 0;
    time_t raw_time = 0;
    struct tm *tm_time = { 0, };
    int fd = -1;
    int ret = 0, rc = SR_ERR_OK;

    /* create the parent directory for notifications (if it does not exist already) */
    strncat(filename_buff, SR_NOTIF_DATA_SEARCH_DIR, filename_buff_size - 1);
    strncat(filename_buff, "/", filename_buff_size - strlen(filename_buff) - 1);
    if (-1 == access(filename_buff, F_OK)) {
        old_umask = umask(0);
        ret = mkdir(filename_buff, S_IRWXU | S_IRWXG | S_IRWXO);
        umask(old_umask);
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", filename_buff,
                sr_strerror_safe(errno));
    }

    /* create directory for module notifications (if it does not exist already) */
    strncat(filename_buff, module_name, filename_buff_size - strlen(filename_buff) - 1);
    strncat(filename_buff, "/", filename_buff_size - strlen(filename_buff) - 1);
    if (-1 == access(filename_buff, F_OK)) {
        old_umask = umask(0);
        ret = mkdir(filename_buff, S_IRWXU | S_IRWXG | S_IRWXO);
        umask(old_umask);
        CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Unable to create the directory '%s': %s", filename_buff,
                sr_strerror_safe(errno));
    }

    /* generate data filename according to the current time */
    raw_time = received_time;
    tm_time = localtime(&raw_time);
    /* move raw_time back to the beginning of the current NP_NOTIF_FILE_WINDOW */
    raw_time -= (((tm_time->tm_hour * 60) + tm_time->tm_min) % SR_NOTIF_TIME_WINDOW) * 60;
    strftime(filename_buff + strlen(filename_buff), filename_buff_size - strlen(filename_buff) - 1,
            "%Y-%m-%d_%H-%M." SR_FILE_FORMAT_EXT, localtime(&raw_time));

    /* create file if not exists & apply access permissions */
    if (-1 == access(filename_buff, F_OK)) {
        old_umask = umask(0);
        fd = open(filename_buff, O_CREAT, S_IRUSR | S_IWUSR);
        if (-1 == fd) {
            SR_LOG_WRN("Error by opening file '%s': %s.", filename_buff, sr_strerror_safe(errno));
        } else {
            /* close and apply access permissions */
            close(fd);
            umask(old_umask);
            rc = sr_set_data_file_permissions(filename_buff, false, SR_DATA_SEARCH_DIR, module_name, false);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Error by applying correct data file permissions on file '%s'.", filename_buff);
            }
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Get notification files of given module with last modification time from provided time interval.
 */
static int
np_get_notification_files(np_ctx_t *np_ctx, const char *module_name, time_t time_from, time_t time_to,
        sr_list_t *file_list)
{
    char dirname[PATH_MAX - 257] = { 0, };
    char filename[PATH_MAX] = { 0, };
    struct dirent **entries = NULL;
    int dir_elem_cnt = 0;
    struct stat sb = { 0, };
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, module_name, file_list);

    if (sr_ll_stderr >= SR_LL_DBG) {
        strftime(dirname, PATH_MAX - 258, "%Y-%m-%d %H:%M", localtime(&time_from));
        strftime(filename, PATH_MAX - 1, "%Y-%m-%d %H:%M", localtime(&time_to));
    }
    SR_LOG_DBG("Listing notification data files for '%s' modified from '%s' to '%s'.", module_name, dirname, filename);

    snprintf(dirname, PATH_MAX - 258, "%s/%s", SR_NOTIF_DATA_SEARCH_DIR, module_name);

    /* scan files in the directory with the data files (in alphabetical order) */
    dir_elem_cnt = scandir(dirname, &entries, NULL, alphasort);
    if (dir_elem_cnt < 0) {
        if (errno != ENOENT) {
            SR_LOG_ERR("Error by scanning directory: %s.", sr_strerror_safe(errno));
        }
    } else {
        for (size_t i = 0; i < dir_elem_cnt; i++) {
            if ((DT_DIR != entries[i]->d_type) &&
                    (0 != strcmp(entries[i]->d_name, ".")) && (0 != strcmp(entries[i]->d_name, ".."))) {
                /* for each file */
                snprintf(filename, PATH_MAX - 1, "%s/%s", dirname, entries[i]->d_name);
                ret = stat(filename, &sb);
                if ((-1 != ret) && (sb.st_mtime >= time_from) && (sb.st_mtime <= time_to)) {
                    /* file modification time matches with provided time interval */
                    SR_LOG_DBG("Adding file '%s', mtim=%ld", filename, sb.st_mtime);
                    rc = sr_list_add(file_list, strdup(filename));
                    if (SR_ERR_OK != rc) {
                        SR_LOG_WRN("Error by adding file '%s' to the list: %s.", filename, sr_strerror(rc));
                    }
                }
            }
            free(entries[i]);
        }
        free(entries);
    }

    return SR_ERR_OK;
}

/**
 * @brief Get notification files of all modules with last modification time from provided time interval.
 */
static int
np_get_all_notification_files(np_ctx_t *np_ctx, time_t time_from, time_t time_to, sr_list_t *file_list)
{
    DIR *dir = { 0, };
    struct dirent entry = { 0, }, *result = NULL;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG2(np_ctx, file_list);

    SR_LOG_DBG("Listing notification directories in '%s'.", SR_NOTIF_DATA_SEARCH_DIR);

    /* open the directory with notifications */
    dir = opendir(SR_NOTIF_DATA_SEARCH_DIR);
    if (NULL == dir) {
        if (errno == ENOENT) {
            SR_LOG_INF("No notification files in '%s': %s.", SR_NOTIF_DATA_SEARCH_DIR, sr_strerror_safe(errno));
            return SR_ERR_OK;
        }
        SR_LOG_ERR("Error by opening directory '%s': %s.", SR_NOTIF_DATA_SEARCH_DIR, sr_strerror_safe(errno));
        return SR_ERR_INTERNAL;
    }
    /* read files in the directory */
    do {
        ret = readdir_r(dir, &entry, &result);
        if (0 != ret) {
            SR_LOG_ERR("Error by reading directory: %s.", sr_strerror_safe(errno));
            break;
        }
        if ((NULL != result) && (0 != strcmp(entry.d_name, ".")) && (0 != strcmp(entry.d_name, ".."))) {
            /* for each directory */
            SR_LOG_DBG("Listing notification directory '%s'.", entry.d_name);
            rc = np_get_notification_files(np_ctx, entry.d_name, time_from, time_to, file_list);
            if (SR_ERR_OK != rc) {
                SR_LOG_WRN("Error by retrieving notification files from '%s' directory: %s.",
                        entry.d_name, sr_strerror(rc));
            }
        }
    } while (NULL != result);
    closedir(dir);

    return SR_ERR_OK;
}

/**
 * @brief cleans up the content of an event notification structure.
 */
static void
np_event_notification_content_cleanup(np_ev_notification_t *notification)
{
    if (NULL != notification) {
        switch (notification->data_type) {
            case NP_EV_NOTIF_DATA_VALUES:
                sr_free_values(notification->data.values, notification->data_cnt);
                break;
            case NP_EV_NOTIF_DATA_TREES:
                sr_free_trees(notification->data.trees, notification->data_cnt);
                break;
            default:
                break;
        }
        free((void*)notification->xpath);
    }
}

/**
 * @brief Fills event notification details from libyang's list instance of a notification.
 */
static int
np_event_notification_entry_fill(np_ev_notification_t *notification, struct lyd_node *node)
{
    struct lyd_node_leaf_list *node_ll = NULL;
    struct lyd_node_anydata *node_anydata = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(notification, node, node->schema);

    while (NULL != node) {
        if (NULL != node->schema && NULL != node->schema->name) {
            node_ll = (struct lyd_node_leaf_list*)node;
            if (0 == strcmp(node->schema->name, "xpath") && NULL != node_ll->value_str) {
                notification->xpath = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(notification->xpath, rc, cleanup);
            }
            if (0 == strcmp(node->schema->name, "generated-time") && NULL != node_ll->value_str) {
                rc = sr_str_to_time((char*)node_ll->value_str, &notification->timestamp);
                CHECK_RC_MSG_GOTO(rc, cleanup, "String to time conversion failed.");
            }
            if (0 == strcmp(node->schema->name, "data") && LYS_ANYDATA == node->schema->nodetype) {
                node_anydata = (struct lyd_node_anydata*)node;
                if (LYD_ANYDATA_XML == node_anydata->value_type) {
                    notification->data.xml = node_anydata->value.xml;
                    notification->data_type = NP_EV_NOTIF_DATA_XML;
                } else if (LYD_ANYDATA_CONSTSTRING == node_anydata->value_type) {
                    notification->data.string = node_anydata->value.str;
                    notification->data_type = NP_EV_NOTIF_DATA_STRING;
                } else if (LYD_ANYDATA_JSON == node_anydata->value_type) {
                    notification->data.string = node_anydata->value.str;
                    notification->data_type = NP_EV_NOTIF_DATA_JSON;
                } else if (LYD_ANYDATA_LYB == node_anydata->value_type) {
                    notification->data.string = node_anydata->value.str;
                    notification->data_type = NP_EV_NOTIF_DATA_LYB;
                }
            }
        }
        node = node->next;
    }

    return SR_ERR_OK;

cleanup:
    np_event_notification_content_cleanup(notification);
    return rc;
}

/**
 * @brief Sets up notification store cleanup timer.
 */
static int
np_setup_notif_store_cleanup_timer(np_ctx_t *np_ctx, uint32_t timeout)
{
    Sr__Msg *req = NULL;
    int rc = SR_ERR_OK;

    /* setup the timer */
    rc = sr_gpb_internal_req_alloc(NULL, SR__OPERATION__NOTIF_STORE_CLEANUP, &req);
    if (SR_ERR_OK == rc) {
        req->internal_request->postpone_timeout = timeout;
        req->internal_request->has_postpone_timeout = true;
        /* enqueue the message */
        rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, req);
    }
    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("Notification store cleanup timer set up for %"PRIu32" seconds.", timeout);
    } else {
        SR_LOG_ERR_MSG("Unable to setup notification store cleanup timer.");
    }

    return rc;
}

/**
 * @brief Logging callback called from libyang for each log entry.
 */
static void
np_ly_log_cb(LY_LOG_LEVEL level, const char *msg, const char *path)
{
    if (LY_LLERR == level) {
        SR_LOG_DBG("libyang error: %s", msg);
    }
}

int
np_init(rp_ctx_t *rp_ctx, const char *schema_search_dir, const char *data_search_dir, np_ctx_t **np_ctx_p)
{
    np_ctx_t *ctx = NULL;
    char *schema_filename = NULL;
    int rc = SR_ERR_OK, ret = 0;

    CHECK_NULL_ARG2(rp_ctx, np_ctx_p);

    /* allocate the context */
    ctx = calloc(1, sizeof(*ctx));
    CHECK_NULL_NOMEM_RETURN(ctx);

    ctx->rp_ctx = rp_ctx;

    /* init binary tree for fast destination info lookup */
    rc = sr_btree_init(np_dst_info_cmp, np_dst_info_cleanup, &ctx->dst_info_btree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate binary tree for destination info lookup.");

    /* init linked-list for commit contexts */
    rc = sr_llist_init(&ctx->commits);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Cannot allocate commits linked-list.");

    /* init subscriptions lock */
    ret = pthread_rwlock_init(&ctx->lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Subscriptions lock initialization failed.");

    /* init notif. data files locking set */
    rc = sr_locking_set_init(&ctx->lock_ctx);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize locking set.");

    /* save data search directory */
    ctx->data_search_dir = strdup(data_search_dir);
    CHECK_NULL_NOMEM_GOTO(ctx->data_search_dir, rc, cleanup);

    /* init libyang ctx */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir, 0);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR_MSG("libyang initialization failed");
        rc = SR_ERR_INIT_FAILED;
        goto cleanup;
    }
    ly_set_log_clb(np_ly_log_cb, 0);

    rc = sr_str_join(schema_search_dir, NP_NS_SCHEMA_FILE, &schema_filename);
    if (SR_ERR_OK != rc) {
        goto cleanup;
    }

    /* load persist files schema to the context */
    ctx->ns_schema = lys_parse_path(ctx->ly_ctx, schema_filename, LYS_IN_YANG);
    free(schema_filename);
    if (NULL == ctx->ns_schema) {
        SR_LOG_ERR("Unable to parse the schema file '%s': %s", NP_NS_SCHEMA_FILE, ly_errmsg(ctx->ly_ctx));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* if running in daemon mode, setup notif. store cleanup timer */
    if (CM_MODE_DAEMON == cm_get_connection_mode(rp_ctx->cm_ctx)) {
        ctx->do_notif_store_cleanup = true;
        np_setup_notif_store_cleanup_timer(ctx, (SR_NOTIF_TIME_WINDOW * 60));
    }

    SR_LOG_DBG_MSG("Notification Processor initialized successfully.");

    *np_ctx_p = ctx;
    return SR_ERR_OK;

cleanup:
    np_cleanup(ctx);
    return rc;
}

void
np_cleanup(np_ctx_t *np_ctx)
{
    sr_llist_node_t *node = NULL;

    SR_LOG_DBG_MSG("Notification Processor cleanup requested.");

    if (NULL != np_ctx) {
        for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
            np_subscription_cleanup(np_ctx->subscriptions[i]);
        }
        free(np_ctx->subscriptions);

        /* cleanup unfinished commits */
        node = np_ctx->commits->first;
        while (NULL != node) {
            free(node->data);
            node = node->next;
        }
        sr_llist_cleanup(np_ctx->commits);

        sr_btree_cleanup(np_ctx->dst_info_btree);
        pthread_rwlock_destroy(&np_ctx->lock);

        sr_locking_set_cleanup(np_ctx->lock_ctx);
        free((void*)np_ctx->data_search_dir);
        if (NULL != np_ctx->ly_ctx) {
            ly_ctx_destroy(np_ctx->ly_ctx, NULL);
        }

        if (np_ctx->do_notif_store_cleanup) {
            np_notification_store_cleanup(np_ctx, false);
        }

        free(np_ctx);
    }
}

/**
 * @brief Function checks whether xpath can be used for the particular subscribe call.
 */
static int
np_validate_subscription_xpath(np_ctx_t *np_ctx, Sr__SubscriptionType type, const char *xpath)
{
    CHECK_NULL_ARG2(np_ctx, xpath);
    int rc = SR_ERR_OK, i;
    char *module_name = NULL;
    dm_schema_info_t *si = NULL;
    struct lys_node *sch_node, *next;
    struct ly_set *set = NULL;
    char *predicate = NULL;

    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == type) {
        /* we do no check for module and subtree subscription at this level */
        return rc;
    } else if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == type) {
        predicate = strchr(xpath, '[');
        if (NULL != predicate) {
            SR_LOG_ERR("Xpath %s contains predicate, it can't be used for subscribe call.", xpath);
            return SR_ERR_UNSUPPORTED;
        }
        return rc;
    } else {
        if (xpath[0] == '/') {
            rc = sr_copy_first_ns(xpath, &module_name);
            CHECK_RC_LOG_RETURN(rc, "Copying module name failed for xpath '%s'", xpath);
        } else {
            module_name = strdup(xpath);
        }

        rc = dm_get_module_and_lock(np_ctx->rp_ctx->dm_ctx, module_name, &si);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Failed to find module %s", module_name);

        if (SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == type) {
            if (xpath[0] == '/') {
                set = lys_find_path(si->module, NULL, xpath);
                if (NULL == set || 0 == set->number) {
                    SR_LOG_ERR("Node identified by xpath %s was not found", xpath);
                    rc = SR_ERR_BAD_ELEMENT;
                    goto cleanup;
                }
                if (1 == set->number) {
                    if (set->set.s[0]->nodetype != LYS_NOTIF) {
                        SR_LOG_ERR("Xpath %s doesn't identify event notification.", xpath);
                        rc = SR_ERR_BAD_ELEMENT;
                    } else if (0 == strcmp(set->set.s[0]->module->name, "nc-notifications")) {
                        if (0 == strcmp(set->set.s[0]->name, "replayComplete")) {
                            SR_LOG_ERR_MSG("You cannot subscribe to the special \"replayComplete\" notification.");
                            rc = SR_ERR_BAD_ELEMENT;
                        } else if (0 == strcmp(set->set.s[0]->name, "notificationComplete")) {
                            SR_LOG_ERR_MSG("You cannot subscribe to the special \"notificationComplete\" notification.");
                            rc = SR_ERR_BAD_ELEMENT;
                        }
                    }
                    goto cleanup;
                }

                /* subscription for more nodes */
                for (i = 0; i < set->number; ++i) {
                    if (set->set.s[i]->nodetype == LYS_NOTIF) {
                        break;
                    }
                }
                if (i == set->number) {
                    SR_LOG_ERR("No notifications identified by xpath %s were found", xpath);
                    rc = SR_ERR_UNSUPPORTED;
                    goto cleanup;
                }
            } else {
                LY_TREE_DFS_BEGIN(si->module->data, next, sch_node) {
                    if (sch_node->nodetype == LYS_NOTIF) {
                        break;
                    }
                    LY_TREE_DFS_END(si->module->data, next, sch_node);
                }
                if (NULL == sch_node) {
                    SR_LOG_ERR("No notifications found in model %s", xpath);
                    rc = SR_ERR_UNSUPPORTED;
                    goto cleanup;
                }
            }
            goto cleanup;
        }

        set = lys_find_path(si->module, NULL, xpath);
        if (NULL == set || 1 != set->number) {
            SR_LOG_ERR("Node identified by xpath %s was not found", xpath);
            rc = SR_ERR_BAD_ELEMENT;
            goto cleanup;
        }
        sch_node = set->set.s[0];

        if (SR__SUBSCRIPTION_TYPE__RPC_SUBS == type && !(LYS_RPC & sch_node->nodetype)) {
            SR_LOG_ERR("Xpath %s doesn't identify RPC.", xpath);
            rc = SR_ERR_UNSUPPORTED;
            goto cleanup;
        } else if (SR__SUBSCRIPTION_TYPE__ACTION_SUBS == type && !(LYS_ACTION & sch_node->nodetype)) {
            SR_LOG_ERR("Xpath %s doesn't identify action.", xpath);
            rc = SR_ERR_UNSUPPORTED;
            goto cleanup;
        } else if (SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == type) {
            if ((LYS_NOTIF | LYS_RPC | LYS_ACTION) & sch_node->nodetype) {
                SR_LOG_ERR("Xpath %s doesn't identify node containing state date.", xpath);
                rc = SR_ERR_UNSUPPORTED;
                goto cleanup;
            }
            predicate = strchr(xpath, '[');
            if (NULL != predicate) {
                SR_LOG_ERR("Xpath %s contains predicate, it can't be used for subscribe call.", xpath);
                rc = SR_ERR_UNSUPPORTED;
                goto cleanup;
            }
        }
    }

cleanup:
    free(module_name);
    ly_set_free(set);
    if (NULL != si) {
        pthread_rwlock_unlock(&si->model_lock);
    }

    return rc;
}

int
np_notification_subscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__SubscriptionType type,
        const char *dst_address, uint32_t dst_id, const char *module_name, const char *xpath, const char *username,
        Sr__NotificationEvent notif_event, uint32_t priority, sr_api_variant_t api_variant, const np_subscr_options_t opts)
{
    np_subscription_t *subscription = NULL;
    np_subscription_t **subscriptions_tmp = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, np_ctx->rp_ctx, rp_session, dst_address);

    SR_LOG_DBG("Notification subscribe: event=%d, dst_address='%s', dst_id=%"PRIu32".", type, dst_address, dst_id);

    /* prepare new subscription entry */
    subscription = calloc(1, sizeof(*subscription));
    CHECK_NULL_NOMEM_RETURN(subscription);

    subscription->type = type;
    if (NULL != module_name) {
        subscription->module_name = strdup(module_name);
        CHECK_NULL_NOMEM_GOTO(subscription->module_name, rc, cleanup);
    }
    if (NULL != xpath) {
        subscription->xpath = strdup(xpath);
        CHECK_NULL_NOMEM_GOTO(subscription->xpath, rc, cleanup);
    }
    if (NULL != username) {
        subscription->username = strdup(username);
        CHECK_NULL_NOMEM_GOTO(subscription->username, rc, cleanup);
    }

    subscription->dst_id = dst_id;
    subscription->dst_address = strdup(dst_address);
    CHECK_NULL_NOMEM_GOTO(subscription->dst_address, rc, cleanup);

    subscription->notif_event = notif_event;
    subscription->priority = priority;
    subscription->enable_running = (opts & NP_SUBSCR_ENABLE_RUNNING);
    subscription->enable_nacm = (rp_session->options & SR_SESS_ENABLE_NACM);
    subscription->api_variant = api_variant;

    if (NULL != xpath) {
        rc = np_validate_subscription_xpath(np_ctx, type, xpath);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Unsupported xpath %s for the subscribe call", xpath);
    }

    /* save the new subscription */
    if ((SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == type) ||
            (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == type) ||
            (SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == type) ||
            (SR__SUBSCRIPTION_TYPE__RPC_SUBS == type) ||
            (SR__SUBSCRIPTION_TYPE__ACTION_SUBS == type) ||
            (SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == type)) {
        /*  update notification destination info */
        rc = np_dst_info_insert(np_ctx, dst_address, module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to update notification destination info.");

        /* enable the module/subtree before the persistent file is edited */
        if (opts & NP_SUBSCR_ENABLE_RUNNING) {
            if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == type || SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == type) {
                /* enable the subtree in running config */
                rc = dm_enable_module_subtree_running(np_ctx->rp_ctx->dm_ctx, rp_session->dm_session, module_name, xpath, opts & NP_SUBSCR_EV_EVENT ? subscription : NULL);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to enable the subtree in the running datastore.");
            } else {
                /* enable the module in running config */
                rc = dm_enable_module_running(np_ctx->rp_ctx->dm_ctx, rp_session->dm_session, module_name, opts & NP_SUBSCR_EV_EVENT ? subscription : NULL);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to enable the module in the running datastore.");
            }
        }

        /* add the subscription to module's persistent data */
        rc = pm_add_subscription(np_ctx->rp_ctx->pm_ctx, rp_session->user_credentials, module_name, subscription,
                (opts & NP_SUBSCR_EXCLUSIVE));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to save the subscription into persistent data file.");

        goto cleanup; /* subscription not needed anymore */
    } else {
        /* add the subscription to in-memory subscription list */
        pthread_rwlock_wrlock(&np_ctx->lock);
        subscriptions_tmp = realloc(np_ctx->subscriptions, (np_ctx->subscription_cnt + 1) * sizeof(*subscriptions_tmp));
        CHECK_NULL_NOMEM_ERROR(subscriptions_tmp, rc);

        if (SR_ERR_OK == rc) {
            np_ctx->subscriptions = subscriptions_tmp;
            np_ctx->subscriptions[np_ctx->subscription_cnt] = subscription;
            np_ctx->subscription_cnt += 1;
            pthread_rwlock_unlock(&np_ctx->lock);
        } else {
            pthread_rwlock_unlock(&np_ctx->lock);
            goto cleanup;
        }
    }

    return SR_ERR_OK;

cleanup:
    if (NULL != subscription) {
        if (SR_ERR_OK != rc) {
            pthread_rwlock_wrlock(&np_ctx->lock);
            np_dst_info_remove(np_ctx, dst_address, module_name);
            pthread_rwlock_unlock(&np_ctx->lock);
        }
        np_subscription_cleanup(subscription);
    }
    return rc;
}

int
np_notification_unsubscribe(np_ctx_t *np_ctx,  const rp_session_t *rp_session, Sr__SubscriptionType notif_type,
        const char *dst_address, uint32_t dst_id, const char *module_name)
{
    np_subscription_t *subscription = NULL, subscription_lookup = { 0, };
    size_t i = 0;
    bool disable_running = true;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, np_ctx->rp_ctx, rp_session, dst_address);

    SR_LOG_DBG("Notification unsubscribe: dst_address='%s', dst_id=%"PRIu32".", dst_address, dst_id);

    if ((SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == notif_type) ||
            (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == notif_type) ||
            (SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS == notif_type) ||
            (SR__SUBSCRIPTION_TYPE__RPC_SUBS == notif_type) ||
            (SR__SUBSCRIPTION_TYPE__ACTION_SUBS == notif_type) ||
            (SR__SUBSCRIPTION_TYPE__EVENT_NOTIF_SUBS == notif_type)) {
        /* remove the subscription to module's persistent data */
        subscription_lookup.dst_address = dst_address;
        subscription_lookup.dst_id = dst_id;
        subscription_lookup.type = notif_type;
        rc = pm_remove_subscription(np_ctx->rp_ctx->pm_ctx, rp_session->user_credentials, module_name,
                &subscription_lookup, &disable_running);
        if (SR_ERR_OK == rc) {
            pthread_rwlock_wrlock(&np_ctx->lock);
            rc = np_dst_info_remove(np_ctx, dst_address, module_name);
            pthread_rwlock_unlock(&np_ctx->lock);
            if (disable_running) {
                SR_LOG_DBG("Disabling running datastore for module '%s'.", module_name);
                rc = dm_disable_module_running(np_ctx->rp_ctx->dm_ctx, rp_session->dm_session, module_name);
                CHECK_RC_LOG_RETURN(rc, "Disabling module %s failed", module_name);
            }
        }
    } else {
        /* remove the subscription from in-memory subscription list */

        /* find matching subscription */
        for (i = 0; i < np_ctx->subscription_cnt; i++) {
            if ((np_ctx->subscriptions[i]->dst_id == dst_id) &&
                    (0 == strcmp(np_ctx->subscriptions[i]->dst_address, dst_address))) {
                subscription = np_ctx->subscriptions[i];
                break;
            }
        }
        if (NULL == subscription) {
            SR_LOG_ERR("Subscription matching with dst_address='%s' and dst_id=%"PRIu32" not found.", dst_address, dst_id);
            return SR_ERR_INVAL_ARG;
        }

        /* remove the subscription from array */
        pthread_rwlock_wrlock(&np_ctx->lock);
        if (np_ctx->subscription_cnt > (i + 1)) {
            memmove(np_ctx->subscriptions + i, np_ctx->subscriptions + i + 1,
                    (np_ctx->subscription_cnt - i - 1) * sizeof(*np_ctx->subscriptions));
        }
        np_ctx->subscription_cnt -= 1;
        pthread_rwlock_unlock(&np_ctx->lock);

        /* release the subscription */
        np_subscription_cleanup(subscription);
    }

    return rc;
}

int
np_unsubscribe_destination(np_ctx_t *np_ctx, const char *dst_address)
{
    np_dst_info_t info_lookup = { 0, }, *info = NULL;
    bool disable_running = true;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(np_ctx, dst_address);

    pthread_rwlock_wrlock(&np_ctx->lock);

    info_lookup.dst_address = dst_address;
    info = sr_btree_search(np_ctx->dst_info_btree, &info_lookup);
    if (NULL != info) {
        for (size_t i = 0; i < info->subscribed_modules_cnt; i++) {
            SR_LOG_DBG("Removing subscriptions for destination '%s' from '%s'.", dst_address,
                    info->subscribed_modules[i]);
            rc = pm_remove_subscriptions_for_destination(np_ctx->rp_ctx->pm_ctx,
                    info->subscribed_modules[i], dst_address, &disable_running);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to remove subscriptions for destination '%s' from '%s'.", dst_address,
                    info->subscribed_modules[i]);
            if (disable_running) {
                SR_LOG_DBG("Disabling running datastore fo module '%s'.", info->subscribed_modules[i]);
                rc = dm_disable_module_running(np_ctx->rp_ctx->dm_ctx, NULL, info->subscribed_modules[i]);
                CHECK_RC_LOG_GOTO(rc, cleanup, "Disabling module %s failed", info->subscribed_modules[i]);
            }
        }
        np_dst_info_remove(np_ctx, dst_address, NULL);
    }
cleanup:
    pthread_rwlock_unlock(&np_ctx->lock);

    return rc;
}

int
np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision,
        sr_module_state_t state)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(np_ctx, module_name);

    SR_LOG_DBG("Sending module-install notifications, module_name='%s', revision='%s', state=%s.",
            module_name, revision, sr_module_state_sr_to_str(state));

    pthread_rwlock_rdlock(&np_ctx->lock);

    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        if (SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS == np_ctx->subscriptions[i]->type) {
            /* allocate the notification */
            rc = sr_gpb_notif_alloc(NULL, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS,
                    np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id, &notif);
            /* fill-in notification details */
            if (SR_ERR_OK == rc) {
                notif->notification->module_install_notif->state = sr_module_state_sr_to_gpb(state);
                notif->notification->module_install_notif->module_name = strdup(module_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->module_install_notif->module_name, rc);
            }
            if (SR_ERR_OK == rc && NULL != revision) {
                notif->notification->module_install_notif->revision = strdup(revision);
                CHECK_NULL_NOMEM_ERROR(notif->notification->module_install_notif->revision, rc);
            }
            /* send the notification */
            if (SR_ERR_OK == rc) {
                SR_LOG_DBG("Sending a module-install notification to the destination address='%s', id=%"PRIu32".",
                        np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id);
                rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
            } else {
                sr_msg_free(notif);
                break;
            }
        }
    }

    pthread_rwlock_unlock(&np_ctx->lock);

    return rc;
}

int
np_feature_enable_notify(np_ctx_t *np_ctx, const char *module_name, const char *feature_name, bool enabled)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, module_name, feature_name);

    SR_LOG_DBG("Sending feature-enable notifications, module_name='%s', feature_name='%s', enabled=%d.",
                module_name, feature_name, enabled);

    pthread_rwlock_rdlock(&np_ctx->lock);

    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        if (SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS == np_ctx->subscriptions[i]->type) {
            /* allocate the notification */
            rc = sr_gpb_notif_alloc(NULL, SR__SUBSCRIPTION_TYPE__FEATURE_ENABLE_SUBS,
                    np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id, &notif);
            /* fill-in notification details */
            if (SR_ERR_OK == rc) {
                notif->notification->feature_enable_notif->enabled = enabled;
                notif->notification->feature_enable_notif->module_name = strdup(module_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->feature_enable_notif->module_name, rc);
            }
            if (SR_ERR_OK == rc) {
                notif->notification->feature_enable_notif->feature_name = strdup(feature_name);
                CHECK_NULL_NOMEM_ERROR(notif->notification->feature_enable_notif->feature_name, rc);
            }
            /* send the notification */
            if (SR_ERR_OK == rc) {
                SR_LOG_DBG("Sending a feature-enable notification to the destination address='%s', id=%"PRIu32".",
                        np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id);
                rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
            } else {
                sr_msg_free(notif);
                break;
            }
        }
    }

    pthread_rwlock_unlock(&np_ctx->lock);

    return rc;
}

int
np_hello_notify(np_ctx_t *np_ctx, const char *module_name, const char *dst_address, uint32_t dst_id)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, np_ctx->rp_ctx, dst_address);

    SR_LOG_DBG("Sending HELLO notification to '%s' @ %"PRIu32".", dst_address, dst_id);

    rc = sr_gpb_notif_alloc(NULL, SR__SUBSCRIPTION_TYPE__HELLO_SUBS, dst_address, dst_id, &notif);

    if (SR_ERR_OK == rc && NULL != module_name) {
        /* save notification destination info */
        rc = np_dst_info_insert(np_ctx, dst_address, module_name);
    }
    if (SR_ERR_OK == rc) {
        /* send the message */
        rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
    } else {
        sr_msg_free(notif);
    }

    return rc;
}

int
np_get_module_change_subscriptions(np_ctx_t *np_ctx, const ac_ucred_t *user_cred, const char *module_name,
        sr_list_t **subscriptions_list)
{
    sr_list_t *subscriptions_list_1 = NULL, *subscriptions_list_2 = NULL;
    np_subscription_t *subscription = NULL;
    size_t total_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, module_name, subscriptions_list);

    /* get subtree-change subscriptions */
    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, user_cred, module_name, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            &subscriptions_list_1);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve subtree-change subscriptions");

    /* get module-change subscriptions */
    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, user_cred, module_name, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            &subscriptions_list_2);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve module-change subscriptions");

    total_cnt += (NULL != subscriptions_list_1) ? subscriptions_list_1->count : 0;
    total_cnt += (NULL != subscriptions_list_2) ? subscriptions_list_2->count : 0;

    if (total_cnt > 0) {
        rc = sr_list_init(subscriptions_list);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize subscriptions list.");

        /* copy subtree-change subscriptions */
        if (NULL != subscriptions_list_1) {
            for (size_t i = 0; i < subscriptions_list_1->count; i++) {
                subscription = subscriptions_list_1->data[i];
                rc = sr_list_add(*subscriptions_list, subscription);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add a subscription to the subscription list.");
            }
            sr_list_cleanup(subscriptions_list_1);
            subscriptions_list_1 = NULL;
        }

        /* copy module-change subscriptions */
        if (NULL != subscriptions_list_2) {
            for (size_t i = 0; i < subscriptions_list_2->count; i++) {
                subscription = subscriptions_list_2->data[i];
                rc = sr_list_add(*subscriptions_list, subscription);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add a subscription to the subscription list.");
            }
            sr_list_cleanup(subscriptions_list_2);
            subscriptions_list_2 = NULL;
        }
    }

cleanup:

    np_subscriptions_list_cleanup(subscriptions_list_1);
    np_subscriptions_list_cleanup(subscriptions_list_2);
    if (SR_ERR_OK != rc) {
        np_subscriptions_list_cleanup(*subscriptions_list);
        *subscriptions_list = NULL;
    }

    return rc;
}

int
np_get_data_provider_subscriptions(np_ctx_t *np_ctx, const rp_session_t *rp_session, const char *module_name,
        sr_list_t **subscriptions)
{
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, rp_session, module_name, subscriptions);

    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, rp_session->user_credentials, module_name,
            SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS, subscriptions);

    return rc;
}

int
np_subscription_notify(np_ctx_t *np_ctx, np_subscription_t *subscription, sr_notif_event_t event, uint32_t commit_id)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;
    np_commit_ctx_t *commit;

    CHECK_NULL_ARG4(np_ctx, np_ctx->rp_ctx, subscription, subscription->dst_address);

    SR_LOG_DBG("Sending %s notification to '%s' @ %"PRIu32".", sr_subscription_type_gpb_to_str(subscription->type),
            subscription->dst_address, subscription->dst_id);

    rc = sr_gpb_notif_alloc(NULL, subscription->type, subscription->dst_address, subscription->dst_id, &notif);

    if (SR_ERR_OK == rc) {
        notif->notification->commit_id = commit_id;
        notif->notification->has_commit_id = true;
        if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type) {
            notif->notification->module_change_notif->event = sr_notification_event_sr_to_gpb(event);
            notif->notification->module_change_notif->module_name = strdup(subscription->module_name);
            CHECK_NULL_NOMEM_ERROR(notif->notification->module_change_notif->module_name, rc);
        }
        if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type) {
            notif->notification->subtree_change_notif->event = sr_notification_event_sr_to_gpb(event);
            notif->notification->subtree_change_notif->xpath = strdup(subscription->xpath);
            CHECK_NULL_NOMEM_ERROR(notif->notification->subtree_change_notif->xpath, rc);
        }
    }

    if (SR_ERR_OK == rc) {
        /* save notification destination info */
        rc = np_dst_info_insert(np_ctx, subscription->dst_address, subscription->module_name);
    }
    if (SR_ERR_OK == rc) {
        /* first create the commit context */
        commit = np_commit_create(np_ctx, commit_id);
        if (!commit) {
            return SR_ERR_INTERNAL;
        }
        /* send the message */
        rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
        if (SR_ERR_OK == rc) {
            commit->notifications_sent++;
        }
    } else {
        sr_msg_free(notif);
    }

    return rc;
}

int
np_data_provider_request(np_ctx_t *np_ctx, np_subscription_t *subscription, rp_session_t *session, const char *xpath)
{
    Sr__Msg *req = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG5(np_ctx, np_ctx->rp_ctx, subscription, subscription->dst_address, xpath);
    CHECK_NULL_ARG2(session, session->req);

    SR_LOG_DBG("Requesting operational data of '%s' from '%s' @ %"PRIu32".", subscription->xpath,
            subscription->dst_address, subscription->dst_id);

    rc = sr_gpb_req_alloc(NULL, SR__OPERATION__DATA_PROVIDE, session->id, &req);

    if (SR_ERR_OK == rc) {
        req->request->data_provide_req->xpath = strdup(xpath);
        CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->xpath, rc);

        if (SR_ERR_OK == rc) {
            req->request->data_provide_req->subscription_id = subscription->dst_id;
            req->request->data_provide_req->subscriber_address = strdup(subscription->dst_address);
            CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->subscriber_address, rc);
            /* identification of the request that asked for data */
            req->request->data_provide_req->request_id = session->req->request->_id;
            switch (session->req->request->operation) {
            case SR__OPERATION__GET_ITEM:
                if (session->req->request->get_item_req->xpath) {
                    req->request->data_provide_req->original_xpath = strdup(session->req->request->get_item_req->xpath);
                    CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->original_xpath, rc);
                }
                break;
            case SR__OPERATION__GET_ITEMS:
                if (session->req->request->get_items_req->xpath) {
                    req->request->data_provide_req->original_xpath = strdup(session->req->request->get_items_req->xpath);
                    CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->original_xpath, rc);
                }
                break;
            case SR__OPERATION__GET_SUBTREE:
                if (session->req->request->get_subtree_req->xpath) {
                    req->request->data_provide_req->original_xpath = strdup(session->req->request->get_subtree_req->xpath);
                    CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->original_xpath, rc);
                }
                break;
            case SR__OPERATION__GET_SUBTREES:
                if (session->req->request->get_subtrees_req->xpath) {
                    req->request->data_provide_req->original_xpath = strdup(session->req->request->get_subtrees_req->xpath);
                    CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->original_xpath, rc);
                }
                break;
            case SR__OPERATION__GET_SUBTREE_CHUNK:
                if (session->req->request->get_subtree_chunk_req->xpath) {
                    req->request->data_provide_req->original_xpath = strdup(session->req->request->get_subtree_chunk_req->xpath);
                    CHECK_NULL_NOMEM_ERROR(req->request->data_provide_req->original_xpath, rc);
                }
                break;
            default:
                break;
            }
        }
    }

    if (SR_ERR_OK == rc) {
        /* save notification destination info */
        rc = np_dst_info_insert(np_ctx, subscription->dst_address, subscription->module_name);
    }
    if (SR_ERR_OK == rc) {
        /* send the message */
        rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, req);
    } else {
        sr_msg_free(req);
    }

    return rc;
}

int
np_commit_notifications_sent(np_ctx_t *np_ctx, uint32_t commit_id, bool commit_finished, sr_list_t *subscriptions)
{
    np_subscription_t *subscription = NULL;
    Sr__Msg *notif = NULL, *req = NULL;
    np_commit_ctx_t *commit = NULL;
    sr_llist_node_t *commit_node = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, np_ctx->rp_ctx, subscriptions);

    if (commit_finished) {
        /* send commit end notifications */
        for (size_t i = 0; i < subscriptions->count; i++) {
            /* send commit_end notification */
            subscription = subscriptions->data[i];
            rc = sr_gpb_notif_alloc(NULL, SR__SUBSCRIPTION_TYPE__COMMIT_END_SUBS, subscription->dst_address,
                    subscription->dst_id, &notif);
            if (SR_ERR_OK == rc) {
                notif->notification->commit_id = commit_id;
                notif->notification->has_commit_id = true;

                /* send the message */
                rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
            }
            notif = NULL;
        }
    }

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, &commit_node);
    if (NULL != commit) {
        commit->all_notifications_sent = true;
        commit->commit_finished = commit_finished;

        /* setup commit timer */
        rc = sr_gpb_internal_req_alloc(NULL, SR__OPERATION__COMMIT_TIMEOUT, &req);
        if (SR_ERR_OK == rc) {
            req->internal_request->commit_timeout_req->commit_id = commit_id;
            if (commit->notifications_acked == commit->notifications_sent) {
                /* all ACKs already received - deliver the msg immediately */
                req->internal_request->commit_timeout_req->expired = false;  /* do not produce error */
                req->internal_request->has_postpone_timeout = false;
            } else {
                /* not all ACKs recieved - deliver the msg after timeout */
                req->internal_request->commit_timeout_req->expired = true;  /* produce error */
                req->internal_request->postpone_timeout = SR_COMMIT_VERIFY_TIMEOUT;
                req->internal_request->has_postpone_timeout = true;
            }
            rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, req);
        }
        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Set up commit timeout for commit id=%"PRIu32".", commit_id);
        } else {
            SR_LOG_ERR("Unable to setup commit timeout for commit id=%"PRIu32".", commit_id);
        }
    }

    pthread_rwlock_unlock(&np_ctx->lock);

    return rc;
}

int
np_commit_notification_ack(np_ctx_t *np_ctx, uint32_t commit_id, char *subs_xpath, sr_notif_event_t event, int result,
        bool do_not_send_abort, const char *err_msg, const char *err_xpath)
{
    np_commit_ctx_t *commit = NULL;
    sr_llist_node_t *commit_node = NULL;
    bool all_acks_received = false;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(np_ctx);

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, &commit_node);

    if (NULL != commit) {
        if (SR_EV_VERIFY == event && SR_ERR_OK != result) {
            /* error returned from the verifier */
            commit->result = result;
            np_commit_error_add(commit, subs_xpath, do_not_send_abort, err_msg, err_xpath);
            SR_LOG_ERR("Verifier for '%s' returned an error (msg: '%s', xpath: '%s'), commit will be aborted.",
                    subs_xpath, err_msg, err_xpath);
        }
        commit->notifications_acked++;
        if (commit->all_notifications_sent && (commit->notifications_sent == commit->notifications_acked)) {
            all_acks_received = true;
        }
    } else {
        SR_LOG_WRN("No NP commit context for commit ID %"PRIu32".", commit_id);
    }

    pthread_rwlock_unlock(&np_ctx->lock);

    if (all_acks_received) {
        /* all notification acks already received - signal DM and possibly release the commit */
        rc = np_commit_notifications_complete(np_ctx, commit_id, false);
    }

    return rc;
}

int
np_commit_notifications_complete(np_ctx_t *np_ctx, uint32_t commit_id, bool timeout_expired)
{
    np_commit_ctx_t *commit = NULL;
    sr_llist_node_t *commit_node = NULL;
    sr_list_t *err_subs_xpaths = NULL, *errors = NULL;
    bool found = false;
    bool finished = false;
    int result = SR_ERR_OK, rc = SR_ERR_OK;

    CHECK_NULL_ARG(np_ctx);

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, &commit_node);
    if (NULL != commit) {
        found = true;
        result = commit->result;
        err_subs_xpaths = commit->err_subs_xpaths;
        errors = commit->errors;
        finished = commit->commit_finished;
        if (commit->commit_finished) {
            /* commit has finished, release commit context */
            SR_LOG_DBG("Releasing commit id=%"PRIu32".", commit_id);
            sr_llist_rm(np_ctx->commits, commit_node);
            free(commit);
            commit = NULL;
        } else {
            /* reset the context for the next commit phase */
            commit->all_notifications_sent = false;
            commit->commit_finished = false;
            commit->err_subs_xpaths = NULL;
            commit->errors = NULL;
        }
    }

    pthread_rwlock_unlock(&np_ctx->lock);

    if (found) {
        SR_LOG_DBG("Commit id=%"PRIu32" notifications complete.", commit_id);

        if (timeout_expired) {
            SR_LOG_ERR("Commit timeout for commit id=%d.", commit_id);
            result = SR_ERR_TIME_OUT;
        }

        /* resume commit processing */
        rc = rp_all_notifications_received(np_ctx->rp_ctx, commit_id, finished, result, err_subs_xpaths, errors);
    }

    return rc;
}

void
np_subscription_content_cleanup(np_subscription_t *subscription)
{
    if (NULL != subscription) {
        free((void*)subscription->dst_address);
        free((void*)subscription->module_name);
        free((void*)subscription->xpath);
        free((void*)subscription->username);
    }
}

void
np_subscription_cleanup(np_subscription_t *subscription)
{
    if (NULL != subscription) {
        if (0 == subscription->copy_cnt) {
            np_subscription_content_cleanup(subscription);
            free(subscription);
        } else {
            subscription->copy_cnt -= 1;
        }
    }
}

void
np_subscriptions_list_cleanup(sr_list_t *subscriptions_list)
{
    if (NULL != subscriptions_list) {
        for (size_t i = 0; i < subscriptions_list->count; i++) {
            np_subscription_cleanup(subscriptions_list->data[i]);
        }
        sr_list_cleanup(subscriptions_list);
    }
}

int
np_store_event_notification(np_ctx_t *np_ctx, const ac_ucred_t *user_cred, const char *xpath, const time_t generated_time,
        struct lyd_node *notif_data_tree)
{
//! @cond doxygen_suppress
#define TIME_BUF_SIZE 64
//! @endcond

    char *module_name = NULL, *tmp_xpath = NULL, *ptr;
    char data_filename[PATH_MAX] = { 0, };
    char data_xpath[PATH_MAX] = { 0, };
    char generated_time_buf[TIME_BUF_SIZE] = { 0, };
    struct timespec logged_time_spec = { 0, };
    struct lyd_node *data_tree = NULL, *new_node = NULL;
    int fd = -1;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(np_ctx, xpath, notif_data_tree);

    SR_LOG_DBG("Storing notification '%s' generated on '%ld'.", xpath, generated_time);

    /* check for special notifications which are not allowed */
    if (0 == strcmp(xpath, "/nc-notifications:replayComplete")) {
        SR_LOG_ERR_MSG("Special notification \"replayComplete\" is generated only by sysrepo itself.");
        rc = SR_ERR_BAD_ELEMENT;
        goto cleanup;
    } else if (0 == strcmp(xpath, "/nc-notifications:notificationComplete")) {
        SR_LOG_ERR_MSG("Special notification \"notificationComplete\" is generated only by sysrepo itself.");
        rc = SR_ERR_BAD_ELEMENT;
        goto cleanup;
    }

    /* extract module name from xpath */
    rc = sr_copy_first_ns(xpath, &module_name);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");

    /* get current notification data filename */
    rc = np_get_notif_store_filename(module_name, generated_time, data_filename, PATH_MAX);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to compose notification data file name for '%s'.", module_name);

    /* load notif. data */
    rc = np_load_data_tree(np_ctx, user_cred, data_filename, false, &data_tree, &fd);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load notification store data for module '%s'.", module_name);

    /* format the time & retrieve current time */
    sr_time_to_str(generated_time, generated_time_buf, TIME_BUF_SIZE);
    sr_clock_get_time(CLOCK_REALTIME, &logged_time_spec);

    /* make sure there will be no invalid quotes */
    if (strchr(xpath, '\'')) {
        tmp_xpath = strdup(xpath);
        for (ptr = strchr(tmp_xpath, '\''); ptr; ptr = strchr(ptr + 1, '\'')) {
            *ptr = '"';
        }
    }

    /* create data subtree to be stored in the notif. data file */
    snprintf(data_xpath, PATH_MAX - 1, NP_NS_XPATH_NOTIFICATION, tmp_xpath ? tmp_xpath : xpath, generated_time_buf,
            /* logged-time in hundreds of seconds */
            (uint32_t) (((logged_time_spec.tv_sec * 100) + (uint32_t)(logged_time_spec.tv_nsec / 1.0e7)) % UINT32_MAX));
    free(tmp_xpath);

    new_node = lyd_new_path(data_tree, np_ctx->ly_ctx, data_xpath, NULL, 0, 0);
    if (NULL == new_node) {
        SR_LOG_WRN("Error by adding new notification entry %s: %s.", data_xpath, ly_errmsg(np_ctx->ly_ctx));
        goto cleanup; /* do not set error code - it may be just too much notifications within the same hundred of second */
    }
    if (NULL == data_tree) {
        /* if the new data tree has been just created */
        data_tree = new_node;
        new_node = new_node->child; /* new_node is 'notifications' container */
    }

    if (0 == strcmp("/ietf-netconf-notifications:netconf-config-change", xpath)) {
        char *string_notif = NULL;
        rc = dm_netconf_config_change_to_string(np_ctx->rp_ctx->dm_ctx, notif_data_tree, &string_notif);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed print config-change notif to string");
        switch (SR_FILE_FORMAT_LY) {
        case LYD_JSON:
            new_node = lyd_new_anydata(new_node, NULL, "data", string_notif, LYD_ANYDATA_JSOND);
            break;
        case LYD_XML:
            new_node = lyd_new_anydata(new_node, NULL, "data", string_notif, LYD_ANYDATA_STRING);
            break;
        case LYD_LYB:
            new_node = lyd_new_anydata(new_node, NULL, "data", string_notif, LYD_ANYDATA_LYBD);
            break;
        default:
            SR_LOG_ERR_MSG("Unknown libyang format '" "SR_FILE_FORMAT_LY" "'.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    } else {
        /* store notification data as anydata */
        if (lyd_print_mem(&ptr, notif_data_tree, SR_FILE_FORMAT_LY, LYP_WITHSIBLINGS | LYP_FORMAT)) {
            SR_LOG_ERR("Error printing notification data tree: %s.", ly_errmsg(notif_data_tree->schema->module->ctx));
            goto cleanup;
        }
        switch (SR_FILE_FORMAT_LY) {
        case LYD_JSON:
            new_node = lyd_new_anydata(new_node, NULL, "data", ptr, LYD_ANYDATA_JSOND);
            break;
        case LYD_XML:
            new_node = lyd_new_anydata(new_node, NULL, "data", ptr, LYD_ANYDATA_SXMLD);
            break;
        case LYD_LYB:
            new_node = lyd_new_anydata(new_node, NULL, "data", ptr, LYD_ANYDATA_LYBD);
            break;
        default:
            SR_LOG_ERR_MSG("Unknown libyang format '" "SR_FILE_FORMAT_LY" "'.");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }
    if (NULL == new_node) {
        SR_LOG_ERR("Error by adding notification content into notification store: %s.", ly_errmsg(notif_data_tree->schema->module->ctx));
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* save notif. data */
    rc = np_save_data_tree(data_tree, fd);
    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("Notification successfully logged into '%s' notification store.", module_name);
    }

cleanup:
    np_cleanup_data_tree(np_ctx, data_tree, fd);
    free(module_name);
    return rc;
}

int
np_get_event_notifications(np_ctx_t *np_ctx, rp_session_t *rp_session, const char *xpath,
        const time_t start_time, const time_t stop_time, const sr_api_variant_t api_variant, sr_list_t **notifications)
{
    char *module_name = NULL;
    char req_xpath[PATH_MAX] = { 0, };
    sr_list_t *file_list = NULL, *notif_list = NULL;
    struct lyd_node *data_tree = NULL, *main_tree = NULL;
    struct ly_set *node_set = NULL;
    np_ev_notification_t *notification = NULL;
    time_t effective_stop_time = 0;
    int rc = SR_ERR_OK, ret = 0;

    CHECK_NULL_ARG3(np_ctx, xpath, notifications);

    effective_stop_time = (0 == stop_time) ? time(NULL) : stop_time;

    SR_LOG_DBG("Loading notifications '%s' generated between '%ld' and '%ld'.", xpath, start_time, effective_stop_time);

    /* extract module name from xpath */
    if (xpath[0] != '/') {
        module_name = strdup(xpath);
        xpath = NULL;
    } else {
        rc = sr_copy_first_ns(xpath, &module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Error by extracting module name from xpath.");
    }

    /* get all notification files matching module name and time interval */
    rc = sr_list_init(&file_list);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize file list.");

    /* get all notification files matching module name and provided time interval */
    rc = np_get_notification_files(np_ctx, module_name,
            (0 == start_time) ? 0 : (start_time - (SR_NOTIF_TIME_WINDOW * 60)),
            (effective_stop_time + (SR_NOTIF_TIME_WINDOW * 60)),
            file_list);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve notification file list.");

    /* load all notification files */
    for (size_t i = 0; i < file_list->count; i++) {
        rc = np_load_data_tree(np_ctx, rp_session->user_credentials, file_list->data[i], true, &data_tree, NULL);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load notification store data for module '%s'.", module_name);
        if (NULL == main_tree) {
            main_tree = data_tree;
        } else {
            ret = lyd_merge(main_tree, data_tree, LYD_OPT_DESTRUCT);
            CHECK_ZERO_LOG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup,
                                "Unable to merge notification trees: %s", ly_errmsg(main_tree->schema->module->ctx));
        }
    }

    /* get all notifications matching the xpath */
    if (NULL == xpath) {
        node_set = lyd_find_path(main_tree, "/*/*");
    } else {
        snprintf(req_xpath, PATH_MAX, NP_NS_XPATH_NOTIFICATION_BY_XPATH, xpath);
        node_set = lyd_find_path(main_tree, req_xpath);
    }

    if (NULL != node_set && node_set->number > 0) {
        /* init the notification list */
        rc = sr_list_init(&notif_list);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to initialize notification list.");

        for (size_t i = 0; i < node_set->number; i++) {
            /* allocate a new notification entry */
            notification = calloc(1, sizeof(*notification));
            CHECK_NULL_NOMEM_GOTO(notification, rc, cleanup);
            /* fill in the notification details */
            rc = np_event_notification_entry_fill(notification, node_set->set.d[i]->child);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Error by filling a notification entry.");

            /* filter out notifications not exactly matching the time interval */
            if (notification->timestamp < start_time || notification->timestamp > effective_stop_time) {
                np_event_notification_cleanup(notification);
                notification = NULL;
                continue;
            }

            /* parse notification data */
            rc = dm_parse_event_notif(np_ctx->rp_ctx, rp_session, NULL, notification, api_variant);
            CHECK_RC_LOG_GOTO(rc, cleanup, "Error by parsing notification '%s'.", notification->xpath);

            SR_LOG_DBG("Adding a new notification: '%s' (time=%ld)", notification->xpath, notification->timestamp);

            /* add the notification into notification list */
            rc = sr_list_add(notif_list, notification);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Error by adding notification into list.");
            notification = NULL;
        }
    }

    *notifications = notif_list;
    notif_list = NULL;

cleanup:
    np_event_notification_cleanup(notification);
    if (NULL != notif_list) {
        /* in case of error */
        for (size_t i = 0; i < notif_list->count; i++) {
            np_event_notification_cleanup(notif_list->data[i]);
        }
        sr_list_cleanup(notif_list);
    }
    ly_set_free(node_set);
    lyd_free_withsiblings(main_tree);
    sr_free_list_of_strings(file_list);
    free(module_name);
    return rc;
}

void
np_event_notification_cleanup(np_ev_notification_t *notification)
{
    if (NULL != notification) {
        np_event_notification_content_cleanup(notification);
        free(notification);
    }
}

int
np_notification_store_cleanup(np_ctx_t *np_ctx, bool reschedule)
{
    sr_list_t *file_list = NULL;
    int ret = 0, rc = SR_ERR_OK;

    CHECK_NULL_ARG(np_ctx);

    SR_LOG_DBG_MSG("Notification store cleanup requested.");

    rc = sr_list_init(&file_list);
    CHECK_RC_MSG_RETURN(rc, "Unable to initialize file list.");

    rc = np_get_all_notification_files(np_ctx, 0, (time(NULL) - (SR_NOTIF_AGE_TIMEOUT * 60)), file_list);

    for (size_t i = 0; i < file_list->count; i++) {
        SR_LOG_DBG("Deleting old notification data file '%s'.", (char*)file_list->data[i]);
        ret = unlink((char*)file_list->data[i]);
        if (-1 == ret) {
            SR_LOG_WRN("Unable to delete notification data file '%s': %s.",
                    (char*)file_list->data[i], sr_strerror_safe(ret));
        }
    }

    sr_free_list_of_strings(file_list);

    if (reschedule) {
        /* setup next notif. store cleanup timer */
        np_setup_notif_store_cleanup_timer(np_ctx, (SR_NOTIF_TIME_WINDOW * 60));
    }

    return rc;
}
