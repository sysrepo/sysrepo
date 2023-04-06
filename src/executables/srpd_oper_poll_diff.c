/**
 * @file srpd_oper_poll_diff.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief oper poll diff subscriptions for sysrepo-plugind
 *
 * @copyright
 * Copyright (c) 2022 Deutsche Telekom AG.
 * Copyright (c) 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#define _GNU_SOURCE

#include "compat.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "bin_common.h"
#include "config.h"
#include "srpd_common.h"

#define SRPD_PLUGIN_NAME "srpd_oper_poll_diff"

/**
 * @brief Internal data struct.
 *
 */
typedef struct {
    sr_session_ctx_t *sess;             /**< implicit plugin session */
    sr_subscription_ctx_t *subscr;      /**< module change subscription */

    struct {
        char *module_name;              /**< subscription module name */
        char *path;                     /**< subscription path */
        sr_subscription_ctx_t *subscr;  /**< oper poll diff subscription */
    } *subs;
    uint32_t sub_count;
} srpd_oper_poll_diff_data_t;

/**
 * @brief Add a new oper poll diff subscription and store it.
 *
 * @param[in] data Data with global state.
 * @param[in] module_name Subscription module name.
 * @param[in] path Oper subscription path.
 * @param[in] valid_ms Oper poll subscription valid time.
 * @param[in] ev_sess Implicit event session for errors.
 * @return SR_ERR value.
 */
static int
srpd_opd_add(srpd_oper_poll_diff_data_t *data, const char *module_name, const char *path, uint32_t valid_ms,
        sr_session_ctx_t *ev_sess)
{
    int rc = SR_ERR_OK;
    void *mem = NULL;
    const sr_error_info_t *err_info;
    const char *format;

    /* alloc new subscription */
    mem = realloc(data->subs, (data->sub_count + 1) * sizeof *data->subs);
    if (!mem) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    data->subs = mem;
    memset(&data->subs[data->sub_count], 0, sizeof *data->subs);

    /* fill */
    data->subs[data->sub_count].module_name = strdup(module_name);
    data->subs[data->sub_count].path = strdup(path);
    if (!data->subs[data->sub_count].module_name || !data->subs[data->sub_count].path) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    if ((rc = sr_oper_poll_subscribe(data->sess, module_name, path, valid_ms, SR_SUBSCR_OPER_POLL_DIFF,
            &data->subs[data->sub_count].subscr))) {
        sr_session_get_error(data->sess, &err_info);
        format = "Failed oper poll subscribe to module \"%s\" path \"%s\" (%s).";

        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, format, module_name, path, err_info->err[0].message);
        sr_session_set_error_message(ev_sess, format, module_name, path, err_info->err[0].message);
        goto cleanup;
    }

    /* valid subscription */
    ++data->sub_count;

cleanup:
    if (rc && mem) {
        free(data->subs[data->sub_count].module_name);
        free(data->subs[data->sub_count].path);
        sr_unsubscribe(data->subs[data->sub_count].subscr);
    }
    return rc;
}

/**
 * @brief Delete an oper poll diff subscription.
 *
 * @param[in] data Data with global state.
 * @param[in] module_name Subscription module name, NULL for all.
 * @param[in] path Oper subscription path, NULL for all.
 */
static void
srpd_opd_del(srpd_oper_poll_diff_data_t *data, const char *module_name, const char *path)
{
    uint32_t i;

    for (i = 0; i < data->sub_count; ++i) {
        if (module_name && strcmp(data->subs[i].module_name, module_name)) {
            continue;
        }
        if (path && strcmp(data->subs[i].path, path)) {
            continue;
        }

        free(data->subs[i].module_name);
        free(data->subs[i].path);
        sr_unsubscribe(data->subs[i].subscr);

        if (module_name && path) {
            /* remove single subscr */
            break;
        }
    }

    if (module_name && path) {
        assert(i < data->sub_count);

        --data->sub_count;
        if (!data->sub_count) {
            free(data->subs);
            data->subs = NULL;
        } else if (i < data->sub_count) {
            /* fill the freed spot */
            data->subs[i] = data->subs[data->sub_count];
        }
    } else {
        /* all subscriptions freed */
        free(data->subs);
        data->subs = NULL;
        data->sub_count = 0;
    }
}

/**
 * @brief Module change callback for oper poll diff configuration.
 */
static int
srpd_oper_poll_diff_change_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t event, uint32_t UNUSED(request_id), void *private_data)
{
    srpd_oper_poll_diff_data_t *data = private_data;
    int rc = SR_ERR_OK, r;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t oper;
    const struct lyd_node *node;
    const char *module_name, *path;
    const struct lyd_node_term *term;
    uint32_t valid_ms;

    if (event == SR_EV_DONE) {
        /* nothing more to do */
        goto cleanup;
    }

    if ((rc = sr_get_changes_iter(session, "/sysrepo-plugind:sysrepo-plugind/oper-datastore/poll-diff-subscription//.",
            &iter))) {
        goto cleanup;
    }

    while (!(r = sr_get_change_tree_next(session, iter, &oper, &node, NULL, NULL, NULL))) {
        if (!strcmp(node->schema->name, "poll-diff-subscription")) {
            node = lyd_child(node);
            assert(node);
            module_name = lyd_get_value(node);

            node = node->next;
            path = lyd_get_value(node);

            term = (struct lyd_node_term *)node->next;
            valid_ms = term->value.uint32;

            if (oper == SR_OP_CREATED) {
                /* add */
                if ((rc = srpd_opd_add(data, module_name, path, valid_ms, session))) {
                    goto cleanup;
                }
            } else {
                assert(oper == SR_OP_DELETED);

                /* del */
                srpd_opd_del(data, module_name, path);
            }
        } else if (!strcmp(node->schema->name, "valid")) {
            if (oper == SR_OP_MODIFIED) {
                node = lyd_child(lyd_parent(node));
                module_name = lyd_get_value(node);

                node = node->next;
                path = lyd_get_value(node);

                term = (struct lyd_node_term *)node->next;
                valid_ms = term->value.uint32;

                /* del and add */
                srpd_opd_del(data, module_name, path);
                if ((rc = srpd_opd_add(data, module_name, path, valid_ms, session))) {
                    goto cleanup;
                }
            } /* else already handled */
        } /* else already handled/ignore */
    }
    if (r != SR_ERR_NOT_FOUND) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Getting next change failed (%s).", sr_strerror(r));
        rc = r;
        goto cleanup;
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

int
srpd_oper_poll_diff_init_cb(sr_session_ctx_t *session, void **private_data)
{
    int rc = SR_ERR_OK;
    srpd_oper_poll_diff_data_t *data = NULL;

    /* alloc data */
    data = calloc(1, sizeof *data);
    if (!data) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /* store session */
    data->sess = session;

    /* subscribe for configuration changes */
    if ((rc = sr_module_change_subscribe(session, "sysrepo-plugind", "/sysrepo-plugind:sysrepo-plugind/oper-datastore/"
            "poll-diff-subscription", srpd_oper_poll_diff_change_cb, data, 0, SR_SUBSCR_ENABLED, &data->subscr))) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Failed to subscribe for changes (%s).", sr_strerror(rc));
        goto cleanup;
    }

cleanup:
    if (rc) {
        if (data) {
            sr_unsubscribe(data->subscr);
            free(data);
        }
    } else {
        *private_data = data;
    }
    return rc;
}

void
srpd_oper_poll_diff_cleanup_cb(sr_session_ctx_t *UNUSED(session), void *private_data)
{
    srpd_oper_poll_diff_data_t *data = private_data;

    sr_unsubscribe(data->subscr);
    srpd_opd_del(data, NULL, NULL);
    free(data);
}
