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

#include "sr_common.h"
#include "access_control.h"
#include "rp_internal.h"
#include "persistence_manager.h"

#define PM_SCHEMA_FILE "sysrepo-persistent-data.yang"  /**< Schema of module's persistent data. */

#define PM_XPATH_MODULE                      "/sysrepo-persistent-data:module[name='%s']"

#define PM_XPATH_FEATURES                     PM_XPATH_MODULE "/enabled-features/feature-name"
#define PM_XPATH_FEATURES_BY_NAME             PM_XPATH_MODULE "/enabled-features/feature-name[.='%s']"

#define PM_XPATH_SUBSCRIPTION_LIST            PM_XPATH_MODULE "/subscriptions/subscription"

#define PM_XPATH_SUBSCRIPTION                 PM_XPATH_SUBSCRIPTION_LIST "[type='%s'][destination-address='%s'][destination-id='%"PRIu32"']"
#define PM_XPATH_SUBSCRIPTION_XPATH           PM_XPATH_SUBSCRIPTION      "/xpath"
#define PM_XPATH_SUBSCRIPTION_EVENT           PM_XPATH_SUBSCRIPTION      "/event"
#define PM_XPATH_SUBSCRIPTION_PRIORITY        PM_XPATH_SUBSCRIPTION      "/priority"
#define PM_XPATH_SUBSCRIPTION_ENABLE_RUNNING  PM_XPATH_SUBSCRIPTION      "/enable-running"

#define PM_XPATH_SUBSCRIPTIONS_BY_TYPE        PM_XPATH_SUBSCRIPTION_LIST "[type='%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_TYPE_XPATH  PM_XPATH_SUBSCRIPTION_LIST "[type='%s'][xpath='%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_DST_ADDR    PM_XPATH_SUBSCRIPTION_LIST "[destination-address='%s']"
#define PM_XPATH_SUBSCRIPTIONS_BY_DST_ID      PM_XPATH_SUBSCRIPTION_LIST "[destination-address='%s'][destination-id='%"PRIu32"']"
#define PM_XPATH_SUBSCRIPTIONS_WITH_E_RUNNING PM_XPATH_SUBSCRIPTION_LIST "[enable-running=true()]"

/**
 * @brief Persistence Manager context.
 */
typedef struct pm_ctx_s {
    rp_ctx_t *rp_ctx;                 /**< Request Processor context. */
    struct ly_ctx *ly_ctx;            /**< libyang context used locally in PM. */
    const struct lys_module *schema;  /**< Schema tree of sysrepo-persistent-data YANG. */
    const char *data_search_dir;      /**< Directory containing the data files. */
    sr_locking_set_t *lock_ctx;        /**< Context for locking persist data files. */
} pm_ctx_t;

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
    ret = lyd_print_fd(fd, data_tree, LYD_XML, LYP_WITHSIBLINGS | LYP_FORMAT);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "Saving persist data tree failed: %s", ly_errmsg());

    /* flush in-core data to the disc */
    ret = fsync(fd);
    CHECK_ZERO_LOG_RETURN(ret, SR_ERR_INTERNAL, "File synchronization failed: %s", sr_strerror_safe(errno));

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

    CHECK_NULL_ARG4(pm_ctx, pm_ctx->rp_ctx, module_name, data_tree);

    rc = sr_get_persist_data_file_name(pm_ctx->data_search_dir, module_name, &data_filename);
    CHECK_RC_LOG_RETURN(rc, "Unable to compose persist data file name for '%s'.", module_name);

    /* open the file as the proper user */
    if (NULL != user_cred) {
        ac_set_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
    }

    fd = open(data_filename, (read_only ? O_RDONLY : O_RDWR));

    if (NULL != user_cred) {
        ac_unset_user_identity(pm_ctx->rp_ctx->ac_ctx);
    }

    if (-1 == fd) {
        /* error by open */
        if (ENOENT == errno) {
            SR_LOG_DBG("Persist data file '%s' does not exist.", data_filename);
            if (read_only) {
                rc = SR_ERR_DATA_MISSING;
            } else {
                /* create new persist file */
                ac_set_user_identity(pm_ctx->rp_ctx->ac_ctx, user_cred);
                fd = open(data_filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
                ac_unset_user_identity(pm_ctx->rp_ctx->ac_ctx);
                if (-1 == fd) {
                    SR_LOG_ERR("Unable to create new persist data file '%s': %s", data_filename, sr_strerror_safe(errno));
                    rc = SR_ERR_INTERNAL;
                }
            }
        } else if (EACCES == errno) {
            SR_LOG_ERR("Insufficient permissions to access persist data file '%s'.", data_filename);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SR_LOG_ERR("Unable to open persist data file '%s': %s.", data_filename, sr_strerror_safe(errno));
            rc = SR_ERR_INTERNAL;
        }
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Persist data tree load for '%s' has failed.", module_name);
            goto cleanup;
        }
    }

    /* lock & load the data tree */
    rc = sr_locking_set_lock_fd(pm_ctx->lock_ctx, fd, data_filename, (read_only ? false : true), true);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to lock persist data file for '%s'.", module_name);

    *data_tree = lyd_parse_fd(pm_ctx->ly_ctx, fd, LYD_XML, LYD_OPT_STRICT | LYD_OPT_CONFIG);
    if (NULL == *data_tree && LY_SUCCESS != ly_errno) {
        SR_LOG_ERR("Parsing persist data from file '%s' failed: %s", data_filename, ly_errmsg());
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
        bool add, bool *running_affected)
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
        new_node = lyd_new_path(*data_tree, pm_ctx->ly_ctx, xpath, value, 0);
        if (NULL == *data_tree) {
            /* if the new data tree has been just created */
            *data_tree = new_node;
        }
        if (NULL == new_node) {
            SR_LOG_ERR("Unable to add new persistent data (xpath=%s): %s.", xpath, ly_errmsg());
            return SR_ERR_DATA_EXISTS;
        }
    } else {
        /* delete persistent data */
        node_set = lyd_get_node(*data_tree, xpath);
        if (NULL == node_set || LY_SUCCESS != ly_errno) {
            SR_LOG_ERR("Unable to find requested persistent data (xpath=%s): %s.", xpath, ly_errmsg());
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
        if (0 == node_set->number) {
            SR_LOG_DBG("Requested persistent data is missing (xpath=%s).", xpath);
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
                SR_LOG_ERR("Unable to delete persistent data (xpath=%s): %s.", xpath, ly_errmsg());
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
        const char *xpath, const char *value, bool add, struct lyd_node **data_tree_p, bool *running_affected)
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

    rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, add, running_affected);
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
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "type")) {
                subscription->type = sr_subsciption_type_str_to_gpb(node_ll->value_str);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "destination-address")) {
                subscription->dst_address = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(subscription->dst_address, rc, cleanup);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "destination-id")) {
                subscription->dst_id = atoi(node_ll->value_str);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "xpath")) {
                subscription->xpath = strdup(node_ll->value_str);
                CHECK_NULL_NOMEM_GOTO(subscription->xpath, rc, cleanup);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "event")) {
                subscription->notif_event = sr_notification_event_str_to_gpb(node_ll->value_str);
            }
            if (NULL != node_ll->value_str && 0 == strcmp(node->schema->name, "priority")) {
                subscription->priority = atoi(node_ll->value_str);
            }
            if (0 == strcmp(node->schema->name, "enable-running")) {
                subscription->enable_running = true;
            }
        }
        node = node->next;
    }

    return SR_ERR_OK;

cleanup:
    np_free_subscription_content(subscription);
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
    node_set = lyd_get_node(data_tree, xpath);
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

    /* initialize libyang */
    ctx->ly_ctx = ly_ctx_new(schema_search_dir);
    if (NULL == ctx->ly_ctx) {
        SR_LOG_ERR("libyang initialization failed: %s", ly_errmsg());
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
        SR_LOG_ERR("Unable to parse the schema file '%s': %s", PM_SCHEMA_FILE, ly_errmsg());
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    *pm_ctx = ctx;
    return SR_ERR_OK;

cleanup:
    pm_cleanup(ctx);
    return rc;
}

void
pm_cleanup(pm_ctx_t *pm_ctx)
{
    if (NULL != pm_ctx) {
        if (NULL != pm_ctx->ly_ctx) {
            ly_ctx_destroy(pm_ctx->ly_ctx, NULL);
        }
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

        rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, feature_name, true, NULL, NULL);

        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Feature '%s' successfully enabled in '%s' persist data tree.", feature_name, module_name);
        }
    } else {
        /* disable the feature */
        snprintf(xpath, PATH_MAX, PM_XPATH_FEATURES_BY_NAME, module_name, feature_name);

        rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, NULL, false, NULL, NULL);

        if (SR_ERR_OK == rc) {
            SR_LOG_DBG("Feature '%s' successfully disabled in '%s' persist file.", feature_name, module_name);
        }
    }

    return rc;
}

int
pm_get_module_info(pm_ctx_t *pm_ctx, const char *module_name, bool *module_enabled,
        char ***subtrees_enabled_p, size_t *subtrees_enabled_cnt_p, char ***features_p, size_t *features_cnt_p)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    struct ly_set *node_set = NULL;
    char **subtrees_enabled = NULL, **features = NULL, **tmp = NULL;
    const char *feature_name = NULL;
    size_t subtrees_enabled_cnt = 0, feature_cnt = 0;
    np_subscription_t subscription = { 0, };
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG3(pm_ctx, module_name, module_enabled);
    CHECK_NULL_ARG4(subtrees_enabled_p, subtrees_enabled_cnt_p, features_p, features_cnt_p);

    *module_enabled = false;
    *subtrees_enabled_p = NULL;
    *subtrees_enabled_cnt_p = 0;
    *features_p = NULL;
    *features_cnt_p = 0;

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, NULL, module_name, true, &data_tree, NULL);
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
    node_set = lyd_get_node(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        features = calloc(node_set->number, sizeof(*features));
        CHECK_NULL_NOMEM_GOTO(features, rc, cleanup);

        for (size_t i = 0; i < node_set->number; i++) {
            feature_name = ((struct lyd_node_leaf_list *)node_set->set.d[i])->value_str;
            if (NULL != feature_name) {
                features[feature_cnt] = strdup(feature_name);
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
    node_set = lyd_get_node(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        for (size_t i = 0; i < node_set->number; i++) {
            memset(&subscription, 0, sizeof(subscription));
            rc = pm_subscription_entry_fill(module_name, &subscription, node_set->set.d[i]->child);
            if (SR_ERR_OK == rc) {
                if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription.type) {
                    *module_enabled = true;
                }
                if (SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription.type) {
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
            np_free_subscription_content(&subscription);
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
        for (size_t i = 0; i < feature_cnt; i++) {
            free((void*)features[i]);
        }
        free(subtrees_enabled);
        free(features);
    }
    return rc;
}

int
pm_add_subscription(pm_ctx_t *pm_ctx, const ac_ucred_t *user_cred, const char *module_name,
        const np_subscription_t *subscription, const bool exclusive)
{
    char xpath[PATH_MAX] = { 0, }, buff[15] = { 0, };
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

        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_TYPE_XPATH, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->xpath);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, NULL, false, NULL);
        if (SR_ERR_OK != rc) {
            SR_LOG_WRN("Unable to delete existing %s subscriptions.", sr_subscription_type_gpb_to_str(subscription->type));
        }
    }

    /* create the subscription */
    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION, module_name,
            sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
    rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, NULL);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new subscription into the data tree.");

    /* set subscription details */
    if (subscription->enable_running) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_ENABLE_RUNNING, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (NULL != subscription->xpath) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_XPATH, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        value = subscription->xpath;
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_EVENT, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        value = sr_notification_event_gpb_to_str(subscription->notif_event);
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }
    if (SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS == subscription->type ||
            SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS == subscription->type) {
        snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION_PRIORITY, module_name,
                sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);
        snprintf(buff, sizeof(buff), "%"PRIu32, subscription->priority);
        value = buff;
        rc = pm_modify_persist_data_tree(pm_ctx, &data_tree, xpath, value, true, NULL);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to add new leaf into the data tree.");
    }

    rc = pm_save_data_tree(data_tree, fd);

    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("Subscription entry successfully added into '%s' persist data tree.", module_name);
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

    *disable_running = false;

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTION, module_name,
            sr_subscription_type_gpb_to_str(subscription->type), subscription->dst_address, subscription->dst_id);

    rc = pm_save_persistent_data(pm_ctx, user_cred, module_name, xpath, NULL, false, &data_tree, &running_affected);
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

    *disable_running = false;

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_DST_ADDR, module_name, dst_address);

    /* remove the subscriptions */
    rc = pm_save_persistent_data(pm_ctx, NULL, module_name, xpath, NULL, false, &data_tree, &running_affected);
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
pm_get_subscriptions(pm_ctx_t *pm_ctx, const char *module_name, Sr__SubscriptionType type,
        np_subscription_t **subscriptions_p, size_t *subscription_cnt_p)
{
    char xpath[PATH_MAX] = { 0, };
    struct lyd_node *data_tree = NULL;
    struct ly_set *node_set = NULL;
    np_subscription_t *subscriptions = NULL;
    size_t subscription_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(pm_ctx, module_name, subscriptions_p, subscription_cnt_p);

    /* load the data tree from persist file */
    rc = pm_load_data_tree(pm_ctx, NULL, module_name, true, &data_tree, NULL);
    CHECK_RC_LOG_GOTO(rc, cleanup, "Unable to load persist data tree for module '%s'.", module_name);

    if (NULL == data_tree) {
        /* empty data file */
        *subscriptions_p = NULL;
        *subscription_cnt_p = 0;
        goto cleanup;
    }

    snprintf(xpath, PATH_MAX, PM_XPATH_SUBSCRIPTIONS_BY_TYPE, module_name, sr_subscription_type_gpb_to_str(type));
    node_set = lyd_get_node(data_tree, xpath);

    if (NULL != node_set && node_set->number > 0) {
        subscriptions = calloc(node_set->number, sizeof(*subscriptions));
        CHECK_NULL_NOMEM_GOTO(subscriptions, rc, cleanup);

        for (size_t i = 0; i < node_set->number; i++) {
            rc = pm_subscription_entry_fill(module_name, &subscriptions[subscription_cnt], node_set->set.d[i]->child);
            CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to fill subscription details.");
            subscription_cnt++;
        }
    }

    SR_LOG_DBG("Returning %zu subscriptions found in '%s' persist file.", subscription_cnt, module_name);

    *subscriptions_p = subscriptions;
    *subscription_cnt_p = subscription_cnt;

cleanup:
    if (NULL != node_set) {
        ly_set_free(node_set);
    }
    if (NULL != data_tree) {
        lyd_free_withsiblings(data_tree);
    }

    if (SR_ERR_OK != rc) {
        np_free_subscriptions(subscriptions, subscription_cnt);
    }

    return rc;
}
