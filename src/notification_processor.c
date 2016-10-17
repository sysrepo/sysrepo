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
#include <inttypes.h>
#include <pthread.h>

#include "sr_common.h"
#include "rp_internal.h"
#include "persistence_manager.h"
#include "notification_processor.h"
#include "request_processor.h"

#define NP_COMMIT_TIMEOUT 10  /**< Timeout (in seconds) after which the commit will be aborted / released
                                   also in case that not all notification ACKs have been received. */

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

    CHECK_NULL_ARG3(np_ctx, dst_address, module_name);

    pthread_rwlock_rdlock(&np_ctx->lock);

    /* find info entry matching with the destination */
    info_lookup.dst_address = dst_address;
    info = sr_btree_search(np_ctx->dst_info_btree, &info_lookup);

    if (NULL != info) {
        /* info entry found */
        for (size_t i = 0; i < info->subscribed_modules_cnt; i++) {
            if (0 == strcmp(info->subscribed_modules[i], module_name)) {
                /* module name already exists within the info entry, no update needed */
                pthread_rwlock_unlock(&np_ctx->lock);
                return SR_ERR_OK;
            }
        }
    }

    /* info update is required */
    pthread_rwlock_unlock(&np_ctx->lock);
    pthread_rwlock_wrlock(&np_ctx->lock);

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

    pthread_rwlock_unlock(&np_ctx->lock);
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
    pthread_rwlock_unlock(&np_ctx->lock);
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
 * @brief Increments count of notifications sent for the commit specified by commit ID.
 */
static int
np_commit_notif_cnt_increment(np_ctx_t *np_ctx, uint32_t commit_id)
{
    np_commit_ctx_t *commit = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(np_ctx);

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, NULL);

    if (NULL == commit) {
        /* add a new commit context */
        SR_LOG_DBG("Creating a new NP commit context for commit ID %"PRIu32".", commit_id);

        commit = calloc(1, sizeof(*commit));
        CHECK_NULL_NOMEM_GOTO(commit, rc, unlock);

        commit->commit_id = commit_id;
        rc = sr_llist_add_new(np_ctx->commits, commit);
    }

    commit->notifications_sent++;

unlock:
    pthread_rwlock_unlock(&np_ctx->lock);

    return rc;
}

/**
 * @brief Adds an error xpath into commit context.
 */
static int
np_commit_error_add(np_commit_ctx_t *commit_ctx, const char *err_subs_xpath, const char *err_msg, const char *err_xpath)
{
    sr_error_info_t *error = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(commit_ctx, err_subs_xpath);

    if (NULL == commit_ctx->err_subs_xpaths) {
        rc = sr_list_init(&commit_ctx->err_subs_xpaths);
        CHECK_RC_MSG_RETURN(rc, "Unable to init sr_list for errored verifier xpaths.");
    }
    rc = sr_list_add(commit_ctx->err_subs_xpaths, strdup(err_subs_xpath));

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

int
np_init(rp_ctx_t *rp_ctx, np_ctx_t **np_ctx_p)
{
    np_ctx_t *ctx = NULL;
    int rc = 0, ret = 0;

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

    /* initialize subscriptions lock */
    ret = pthread_rwlock_init(&ctx->lock, NULL);
    CHECK_ZERO_MSG_GOTO(ret, rc, SR_ERR_INTERNAL, cleanup, "Subscriptions lock initialization failed.");

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
            np_free_subscription(np_ctx->subscriptions[i]);
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
        free(np_ctx);
    }
}

int
np_notification_subscribe(np_ctx_t *np_ctx, const rp_session_t *rp_session, Sr__SubscriptionType type,
        const char *dst_address, uint32_t dst_id, const char *module_name, const char *xpath,
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

    subscription->dst_id = dst_id;
    subscription->dst_address = strdup(dst_address);
    CHECK_NULL_NOMEM_GOTO(subscription->dst_address, rc, cleanup);

    subscription->notif_event = notif_event;
    subscription->priority = priority;
    subscription->enable_running = (opts & NP_SUBSCR_ENABLE_RUNNING);
    subscription->api_variant = api_variant;

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
                rc = dm_enable_module_subtree_running(np_ctx->rp_ctx->dm_ctx, rp_session->dm_session, module_name, xpath, true);
                CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to enable the subtree in the running datastore.");
            } else {
                /* enable the module in running config */
                rc = dm_enable_module_running(np_ctx->rp_ctx->dm_ctx, rp_session->dm_session, module_name, true);
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
        np_free_subscription(subscription);
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
        np_free_subscription(subscription);
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
np_module_install_notify(np_ctx_t *np_ctx, const char *module_name, const char *revision, bool installed)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(np_ctx, module_name);

    SR_LOG_DBG("Sending module-install notifications, module_name='%s', revision='%s', installed=%d.",
            module_name, revision, installed);

    pthread_rwlock_rdlock(&np_ctx->lock);

    for (size_t i = 0; i < np_ctx->subscription_cnt; i++) {
        if (SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS == np_ctx->subscriptions[i]->type) {
            /* allocate the notification */
            rc = sr_gpb_notif_alloc(NULL, SR__SUBSCRIPTION_TYPE__MODULE_INSTALL_SUBS,
                    np_ctx->subscriptions[i]->dst_address, np_ctx->subscriptions[i]->dst_id, &notif);
            /* fill-in notification details */
            if (SR_ERR_OK == rc) {
                notif->notification->module_install_notif->installed = installed;
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
np_get_module_change_subscriptions(np_ctx_t *np_ctx, const char *module_name,
        np_subscription_t ***subscriptions_arr_p, size_t *subscriptions_cnt_p)
{
    np_subscription_t *subscriptions_1 = NULL, *subscriptions_2 = NULL, **subscriptions_arr = NULL;
    size_t subscription_cnt_1 = 0, subscription_cnt_2 = 0, subscriptions_arr_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, module_name, subscriptions_arr_p, subscriptions_cnt_p);

    /* get subtree-change subscriptions */
    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, module_name, SR__SUBSCRIPTION_TYPE__SUBTREE_CHANGE_SUBS,
            &subscriptions_1, &subscription_cnt_1);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve subtree-change subscriptions");

    /* get module-change subscriptions */
    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, module_name, SR__SUBSCRIPTION_TYPE__MODULE_CHANGE_SUBS,
            &subscriptions_2, &subscription_cnt_2);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve module-change subscriptions");

    if ((subscription_cnt_1 + subscription_cnt_2) > 0) {
        /* allocate array of pointers to be returned */
        subscriptions_arr = calloc(subscription_cnt_1 + subscription_cnt_2, sizeof(*subscriptions_arr));
        CHECK_NULL_NOMEM_GOTO(subscriptions_arr, rc, cleanup);

        /* copy subtree-change subscriptions */
        for (size_t i = 0; i < subscription_cnt_1; i++) {
            subscriptions_arr[subscriptions_arr_cnt] = calloc(1, sizeof(**subscriptions_arr));
            CHECK_NULL_NOMEM_GOTO(subscriptions_arr[subscriptions_arr_cnt], rc, cleanup);
            memcpy(subscriptions_arr[subscriptions_arr_cnt], &subscriptions_1[i], sizeof(subscriptions_1[i]));
            subscriptions_arr_cnt++;
        }
        free(subscriptions_1);
        subscriptions_1 = NULL;

        /* copy module-change subscriptions */
        for (size_t i = 0; i < subscription_cnt_2; i++) {
            subscriptions_arr[subscriptions_arr_cnt] = calloc(1, sizeof(**subscriptions_arr));
            CHECK_NULL_NOMEM_GOTO(subscriptions_arr[subscriptions_arr_cnt], rc, cleanup);
            memcpy(subscriptions_arr[subscriptions_arr_cnt], &subscriptions_2[i], sizeof(subscriptions_2[i]));
            subscriptions_arr_cnt++;
        }
        free(subscriptions_2);
        subscriptions_2 = NULL;
    }

    *subscriptions_arr_p = subscriptions_arr;
    *subscriptions_cnt_p = subscriptions_arr_cnt;

    return SR_ERR_OK;

cleanup:
    np_free_subscriptions(subscriptions_1, subscription_cnt_1);
    np_free_subscriptions(subscriptions_2, subscription_cnt_2);
    for (size_t i = 0; i < subscriptions_arr_cnt; i++) {
        free(subscriptions_arr[i]);
    }
    free(subscriptions_arr);
    return rc;
}

int
np_get_data_provider_subscriptions(np_ctx_t *np_ctx, const char *module_name,
        np_subscription_t ***subscriptions_arr_p, size_t *subscriptions_cnt_p)
{
    np_subscription_t *subscriptions = NULL, **subscriptions_arr = NULL;
    size_t subscription_cnt = 0, subscriptions_arr_cnt = 0;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG4(np_ctx, module_name, subscriptions_arr_p, subscriptions_cnt_p);

    /* get data provides subscriptions */
    rc = pm_get_subscriptions(np_ctx->rp_ctx->pm_ctx, module_name, SR__SUBSCRIPTION_TYPE__DP_GET_ITEMS_SUBS,
            &subscriptions, &subscription_cnt);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Unable to retrieve subtree-change subscriptions");

    if (subscription_cnt > 0) {
        /* allocate array of pointers to be returned */
        subscriptions_arr = calloc(subscription_cnt, sizeof(*subscriptions_arr));
        CHECK_NULL_NOMEM_GOTO(subscriptions_arr, rc, cleanup);

        /* copy the subscriptions */
        for (size_t i = 0; i < subscription_cnt; i++) {
            subscriptions_arr[subscriptions_arr_cnt] = calloc(1, sizeof(**subscriptions_arr));
            CHECK_NULL_NOMEM_GOTO(subscriptions_arr[subscriptions_arr_cnt], rc, cleanup);
            memcpy(subscriptions_arr[subscriptions_arr_cnt], &subscriptions[i], sizeof(subscriptions[i]));
            subscriptions_arr_cnt++;
        }
        free(subscriptions);
        subscriptions = NULL;
    }

    *subscriptions_arr_p = subscriptions_arr;
    *subscriptions_cnt_p = subscriptions_arr_cnt;

    return SR_ERR_OK;

cleanup:
    np_free_subscriptions(subscriptions, subscription_cnt);
    for (size_t i = 0; i < subscriptions_arr_cnt; i++) {
        free(subscriptions_arr[i]);
    }
    free(subscriptions_arr);
    return rc;
}

int
np_subscription_notify(np_ctx_t *np_ctx, np_subscription_t *subscription, sr_notif_event_t event, uint32_t commit_id)
{
    Sr__Msg *notif = NULL;
    int rc = SR_ERR_OK;

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
        /* send the message */
        rc = cm_msg_send(np_ctx->rp_ctx->cm_ctx, notif);
        if (SR_ERR_OK == rc) {
            rc = np_commit_notif_cnt_increment(np_ctx, commit_id);
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
            req->request->data_provide_req->request_id = (uint64_t) session->req;
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
                req->internal_request->postpone_timeout = NP_COMMIT_TIMEOUT;
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
        const char *err_msg, const char *err_xpath)
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
            if (SR_ERR_OK == commit->result) {
                /* if there isn't any previous error stored within the commit context, store there this one */
                commit->result = result;
            }
            if (SR_ERR_OK != result) {
                np_commit_error_add(commit, subs_xpath, err_msg, err_xpath);
            }
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
    int result = SR_ERR_OK, rc = SR_ERR_OK;

    CHECK_NULL_ARG(np_ctx);

    pthread_rwlock_wrlock(&np_ctx->lock);

    commit = np_commit_ctx_find(np_ctx, commit_id, &commit_node);
    if (NULL != commit) {
        found = true;
        result = commit->result;
        err_subs_xpaths = commit->err_subs_xpaths;
        errors = commit->errors;
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
        rc = rp_resume_commit(np_ctx->rp_ctx, commit_id, result, err_subs_xpaths, errors);
    }

    return rc;
}

void
np_free_subscription(np_subscription_t *subscription)
{
    if (NULL != subscription) {
        np_free_subscription_content(subscription);
        free(subscription);
    }
}

void
np_free_subscription_content(np_subscription_t *subscription)
{
    if (NULL != subscription) {
        free((void*)subscription->dst_address);
        free((void*)subscription->module_name);
        free((void*)subscription->xpath);
    }
}

void
np_free_subscriptions(np_subscription_t *subscriptions, size_t subscriptions_cnt)
{
    for (size_t i = 0; i < subscriptions_cnt; i++) {
        np_free_subscription_content(&subscriptions[i]);
    }
    free(subscriptions);
}
