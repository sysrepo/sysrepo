/**
 * @file sn_yang_push.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ietf-subscribed-notifications yang-push functions
 *
 * @copyright
 * Copyright (c) 2023 Deutsche Telekom AG.
 * Copyright (c) 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "sn_yang_push.h"

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "sn_common.h"
#include "subscribed_notifications.h"
#include "sysrepo.h"

void
srsn_yp_reset_patch_id(struct srsn_sub *sub)
{
    sub->patch_id = 1;
}

sr_error_info_t *
srsn_yp_ntf_update_send(struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    sr_session_ctx_t *sr_sess = NULL;
    struct lyd_node *ly_ntf = NULL;
    struct timespec ts;
    sr_data_t *data = NULL;
    char buf[11];
    int r;

    /* start a new session */
    if ((r = sr_session_start(sub->conn, sub->ds, &sr_sess))) {
        sr_errinfo_new(&err_info, r, "Failed to start a new SR session.");
        goto cleanup;
    }

    /* get the data from sysrepo */
    if ((r = sr_get_data(sr_sess, sub->xpath_filter ? sub->xpath_filter : "/*", 0, 0, 0, &data))) {
        err_info = sr_sess->err_info;
        sr_sess->err_info = NULL;
        goto cleanup;
    }

    /* create the notification */
    sprintf(buf, "%" PRIu32, sub->id);
    if (lyd_new_path(NULL, sub->conn->ly_ctx, "/ietf-yang-push:push-update/id", buf, 0, &ly_ntf)) {
        sr_errinfo_new_ly(&err_info, sub->conn->ly_ctx, NULL);
        goto cleanup;
    }

    /* datastore-contents */
    if (lyd_new_any(ly_ntf, NULL, "datastore-contents", data ? data->tree : NULL, 1, LYD_ANYDATA_DATATREE, 0, NULL)) {
        sr_errinfo_new_ly(&err_info, sub->conn->ly_ctx, NULL);
        goto cleanup;
    }
    if (data) {
        data->tree = NULL;
    }

    /* send the notification */
    sr_realtime_get(&ts);
    if ((err_info = srsn_ntf_send(sub, &ts, ly_ntf))) {
        goto cleanup;
    }

cleanup:
    lyd_free_tree(ly_ntf);
    sr_release_data(data);
    sr_session_stop(sr_sess);
    return err_info;
}

/**
 * @brief Timer callback for push-update notification of periodic yang-push subscriptions.
 */
static void
srsn_yp_update_timer_cb(void *arg, int *UNUSED(freed))
{
    struct srsn_sub *sub = arg;
    sr_error_info_t *err_info = NULL;

    /* send the push-update notification */
    if ((err_info = srsn_yp_ntf_update_send(sub))) {
        sr_errinfo_free(&err_info);
    }
}

sr_error_info_t *
srsn_yp_schedule_periodic_update(uint32_t period_ms, const struct timespec *anchor_time, struct srsn_sub *sub,
        struct srsn_timer *sntimer)
{
    sr_error_info_t *err_info = NULL;
    struct timespec trigger, interval;
    int anchor_ms;

    /* set the trigger timestamp */
    sr_realtime_get(&trigger);
    if (anchor_time) {
        /* first update at nearest anchor time on period */
        anchor_ms = sr_time_sub_ms(&trigger, anchor_time);
        if (anchor_ms < 0) {
            anchor_ms *= -1;
        }
        anchor_ms %= period_ms;
        trigger = sr_time_ts_add(&trigger, anchor_ms);
    }

    /* set the interval */
    interval.tv_sec = period_ms / 1000;
    interval.tv_nsec = (period_ms % 1000) * 1000000;

    if (!sntimer->tid) {
        /* create the timer */
        if ((err_info = srsn_create_timer(srsn_yp_update_timer_cb, sub, &trigger, &interval, sntimer))) {
            goto cleanup;
        }
    } else {
        /* update the timer */
        srsn_update_timer(&trigger, &interval, sntimer);
    }

cleanup:
    return err_info;
}

/**
 * @brief Send a prepared yang-push on-change change notification.
 *
 * @param[in] sub Subscription to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_ntf_change_send(struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    struct timespec ts;

    sr_realtime_get(&ts);
    if ((err_info = srsn_ntf_send(sub, &ts, sub->change_ntf->tree))) {
        return err_info;
    }
    sr_release_data(sub->change_ntf);
    sub->change_ntf = NULL;

    /* set last_notif timestamp */
    sub->last_notif = ts;

    return NULL;
}

/**
 * @brief Timer callback for dampened on-change yang-push changes.
 */
static void
srsn_yp_damp_timer_cb(void *arg, int *UNUSED(freed))
{
    struct srsn_sub *sub = arg;
    sr_error_info_t *err_info = NULL;

    /* send the postponed on-change notification */
    if ((err_info = srsn_yp_ntf_change_send(sub))) {
        sr_errinfo_free(&err_info);
    }
}

/**
 * @brief Check whether an on-change yang-push notification is ready to be sent or will be postponed.
 *
 * @param[in] sub Subscription to use.
 * @param[out] ready Whether the notification can be sent or was scheduled to be sent later.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_ntf_change_ready(struct srsn_sub *sub, int *ready)
{
    sr_error_info_t *err_info = NULL;
    struct timespec next_notif, cur_time;
    int next_notif_in;

    if (!sub->dampening_period_ms) {
        /* always ready */
        *ready = 1;
        return NULL;
    }

    if (sub->damp_sntimer.tid) {
        /* timer is already set */
        *ready = 0;
        return NULL;
    }

    /* learn when the next notification is due */
    sr_realtime_get(&cur_time);
    next_notif = sr_time_ts_add(&sub->last_notif, sub->dampening_period_ms);
    next_notif_in = sr_time_sub_ms(&next_notif, &cur_time);

    if (next_notif_in <= 0) {
        /* can be sent */
        *ready = 1;
        return NULL;
    }

    /* create the timer */
    if ((err_info = srsn_create_timer(srsn_yp_damp_timer_cb, sub, &next_notif, NULL, &sub->damp_sntimer))) {
        return err_info;
    }

    *ready = 0;
    return NULL;
}

/**
 * @brief Transform operation from sysrepo to yang-push.
 *
 * @param[in] op Sysrepo operation.
 * @param[in] node Changed node returned by sysrepo.
 * @return yang-push change (operation).
 */
static srsn_yp_change_t
srsn_yp_op_sr2yp(sr_change_oper_t op, const struct lyd_node *node)
{
    switch (op) {
    case SR_OP_CREATED:
        if (lysc_is_userordered(node->schema)) {
            return SRSN_YP_CHANGE_INSERT;
        }
        return SRSN_YP_CHANGE_CREATE;
    case SR_OP_MODIFIED:
        return SRSN_YP_CHANGE_REPLACE;
    case SR_OP_DELETED:
        return SRSN_YP_CHANGE_DELETE;
    case SR_OP_MOVED:
        return SRSN_YP_CHANGE_MOVE;
    }

    return SRSN_YP_CHANGE_INVALID;
}

/**
 * @brief Transform yang-push operation into string.
 *
 * @param[in] op yang-push operation.
 * @return String operation name.
 */
static const char *
srsn_yp_op2str(srsn_yp_change_t op)
{
    switch (op) {
    case SRSN_YP_CHANGE_INVALID:
        break;
    case SRSN_YP_CHANGE_CREATE:
        return "create";
    case SRSN_YP_CHANGE_DELETE:
        return "delete";
    case SRSN_YP_CHANGE_INSERT:
        return "insert";
    case SRSN_YP_CHANGE_MOVE:
        return "move";
    case SRSN_YP_CHANGE_REPLACE:
        return "replace";
    case SRSN_COUNT_YP_CHANGE:
        break;
    }

    return NULL;
}

/**
 * @brief Remove any previous edits in a YANG patch of a target.
 *
 * @param[in] ly_yp YANG patch node.
 * @param[in] target Target edits to remove.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_ntf_change_edit_clear_target(struct lyd_node *ly_yp, const char *target)
{
    sr_error_info_t *err_info = NULL;
    struct ly_set *set = NULL;
    char quot, *xpath = NULL;

    /* find the edit of this target, be careful with the quotes in the XPath */
    quot = strchr(target, '\'') ? '\"' : '\'';
    if (asprintf(&xpath, "/ietf-yang-push:push-change-update/datastore-changes/yang-patch/edit[target=%c%s%c]",
            quot, target, quot) == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    if (lyd_find_xpath(ly_yp, xpath, &set)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(ly_yp), NULL);
        goto cleanup;
    }
    assert((set->count == 0) || (set->count == 1));

    /* remove the previous change of this target */
    if (set->count) {
        lyd_free_tree(set->dnodes[0]);
    }

cleanup:
    free(xpath);
    ly_set_free(set, NULL);
    return err_info;
}

/**
 * @brief Append a new edit (change) to a YANG patch.
 *
 * @param[in] ly_yp YANG patch node to append to.
 * @param[in] yp_op yang-push operation.
 * @param[in] node Changed node.
 * @param[in] prev_value Previous leaf-list value, if any.
 * @param[in] prev_list Previous list value, if any.
 * @param[in] sub Subscription to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_ntf_change_edit_append(struct lyd_node *ly_yp, srsn_yp_change_t yp_op, const struct lyd_node *node,
        const char *prev_value, const char *prev_list, struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *ly_edit, *ly_target, *value_tree = NULL;
    char buf[26], *path = NULL, *point = NULL, quot, *xml;
    uint32_t edit_id;

    /* get the edit target path */
    path = lyd_path(node, LYD_PATH_STD, NULL, 0);
    SR_CHECK_MEM_GOTO(!path, err_info, cleanup);

    /* remove any previous change of this target */
    if ((err_info = srsn_yp_ntf_change_edit_clear_target(ly_yp, path))) {
        goto cleanup;
    }

    /* generate new edit ID */
    edit_id = sub->edit_id++;

    /* edit with edit-id */
    sprintf(buf, "edit-%" PRIu32, edit_id);
    if (lyd_new_list(ly_yp, NULL, "edit", 0, &ly_edit, buf)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(ly_yp), NULL);
        goto cleanup;
    }

    /* operation */
    if (lyd_new_term(ly_edit, NULL, "operation", srsn_yp_op2str(yp_op), 0, NULL)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
        goto cleanup;
    }

    /* target */
    if (lyd_new_term(ly_edit, NULL, "target", path, 0, &ly_target)) {
        sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
        goto cleanup;
    }

    if ((yp_op == SRSN_YP_CHANGE_INSERT) || (yp_op == SRSN_YP_CHANGE_MOVE)) {
        /* point */
        if (node->schema->nodetype == LYS_LEAFLIST) {
            assert(prev_value);
            if (prev_value[0]) {
                quot = strchr(prev_value, '\'') ? '\"' : '\'';
                if (asprintf(&point, "%s[.=%c%s%c]", path, quot, prev_value, quot) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }
            }
        } else {
            if (prev_list[0]) {
                if (asprintf(&point, "%s%s", path, prev_list) == -1) {
                    SR_ERRINFO_MEM(&err_info);
                    goto cleanup;
                }
            }
        }
        if (point && lyd_new_term(ly_edit, NULL, "point", point, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
            goto cleanup;
        }

        /* where */
        if (((node->schema->nodetype == LYS_LEAFLIST) && !prev_value[0]) ||
                ((node->schema->nodetype == LYS_LIST) && !prev_list[0])) {
            if (lyd_new_term(ly_edit, NULL, "where", "first", 0, NULL)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
                goto cleanup;
            }
        } else {
            if (lyd_new_term(ly_edit, NULL, "where", "after", 0, NULL)) {
                sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
                goto cleanup;
            }
        }
    }

    if ((yp_op == SRSN_YP_CHANGE_INSERT) || (yp_op == SRSN_YP_CHANGE_CREATE) || (yp_op == SRSN_YP_CHANGE_REPLACE)) {
        /* duplicate value tree without metadata */
        if (lyd_dup_single(node, NULL, LYD_DUP_RECURSIVE | LYD_DUP_NO_META | LYD_DUP_WITH_FLAGS, &value_tree)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
            goto cleanup;
        }

        /* value, add as an XML subtree so that it can be printed in LYB */
        if (lyd_print_mem(&xml, value_tree, LYD_XML, LYD_PRINT_SHRINK | LYD_PRINT_WD_ALL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(node), NULL);
            goto cleanup;
        }
        assert(xml);
        if (lyd_new_any(ly_edit, NULL, "value", xml, 1, LYD_ANYDATA_XML, 0, NULL)) {
            sr_errinfo_new_ly(&err_info, LYD_CTX(ly_edit), NULL);
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(point);
    lyd_free_tree(value_tree);
    if (err_info) {
        sr_errinfo_new(&err_info, err_info->err[0].err_code, "Failed to store data edit for an on-change notification.");
    }
    return err_info;
}

/**
 * @brief Module change callback for yang-push data changes.
 */
static int
srsn_yp_on_change_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *module_name,
        const char *xpath, sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *private_data)
{
    sr_error_info_t *err_info = NULL;
    struct srsn_sub *sub = private_data;
    char *xp = NULL, buf[26];
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const struct ly_ctx *ly_ctx;
    struct lyd_node *ly_yp = NULL;
    const char *prev_value, *prev_list;
    srsn_yp_change_t yp_op;
    int ready, r;
    uint32_t patch_id;

    assert(sub->type == SRSN_YANG_PUSH_ON_CHANGE);

    if (xpath) {
        r = asprintf(&xp, "%s//.", xpath);
    } else {
        r = asprintf(&xp, "/%s:*//.", module_name);
    }
    SR_CHECK_MEM_GOTO(r == -1, err_info, cleanup);
    if (sr_get_changes_iter(session, xp, &iter)) {
        err_info = session->err_info;
        session->err_info = NULL;
        goto cleanup;
    }

    /* TIMER LOCK */
    pthread_mutex_lock(&sub->damp_sntimer.lock);

    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, NULL)) {
        /* learn yang-push operation */
        yp_op = srsn_yp_op_sr2yp(op, node);
        if (sub->excluded_changes[yp_op]) {
            /* excluded */
            ++sub->excluded_change_count;
            continue;
        }

        assert(!sub->change_ntf || sub->change_ntf->tree);

        /* there is a change */
        if (!sub->change_ntf) {
            /* store as SR data with context lock, is unlocked on error */
            ly_ctx = sr_acquire_context(sub->conn);
            if ((r = sr_acquire_data(sub->conn, NULL, &sub->change_ntf))) {
                sr_errinfo_new(&err_info, r, "Failed to acquire data.");
                goto cleanup_unlock;
            }

            /* create basic structure for push-change-update notification */
            sprintf(buf, "%" PRIu32, sub->id);
            if (lyd_new_path(NULL, ly_ctx, "/ietf-yang-push:push-change-update/id", buf, 0, &sub->change_ntf->tree)) {
                sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
                goto cleanup_unlock;
            }

            /* generate a new patch-id */
            patch_id = sub->patch_id++;
            sprintf(buf, "patch-%" PRIu32, patch_id);
            if (lyd_new_path(sub->change_ntf->tree, NULL, "datastore-changes/yang-patch/patch-id", buf, 0, NULL)) {
                sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
                goto cleanup_unlock;
            }

            /* initialize edit-id */
            sub->edit_id = 1;
        }
        if (!ly_yp) {
            ly_yp = lyd_child(lyd_child(sub->change_ntf->tree)->next);
        }

        /* append a new edit */
        if ((err_info = srsn_yp_ntf_change_edit_append(ly_yp, yp_op, node, prev_value, prev_list, sub))) {
            goto cleanup_unlock;
        }
    }

    if (!sub->change_ntf) {
        /* there are actually no changes */
        goto cleanup_unlock;
    }

    /* check whether the notification can be sent now */
    if ((err_info = srsn_yp_ntf_change_ready(sub, &ready))) {
        goto cleanup_unlock;
    }

    /* send the notification */
    if (ready && (err_info = srsn_yp_ntf_change_send(sub))) {
        goto cleanup_unlock;
    }

cleanup_unlock:
    if (err_info && sub->change_ntf) {
        sr_release_data(sub->change_ntf);
        sub->change_ntf = NULL;
    }

    /* TIMER UNLOCK */
    pthread_mutex_unlock(&sub->damp_sntimer.lock);

cleanup:
    free(xp);
    sr_free_change_iter(iter);

    /* return value is ignored anyway */
    sr_errinfo_free(&err_info);
    return SR_ERR_OK;
}

/**
 * @brief Subscribe to module changes of a module.
 *
 * @param[in] ly_mod Module to subscribe to.
 * @param[in] sess Sysrepo session.
 * @param[in] sub_no_thread Create the subscriptions without a managing thread.
 * @param[in] sub Subscription to use.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_sr_subscribe_mod(const struct lys_module *ly_mod, sr_session_ctx_t *sess, int sub_no_thread,
        struct srsn_sub *sub)
{
    sr_error_info_t *err_info = NULL;
    void *mem;
    uint32_t sub_opts;

    /* allocate a new sub ID */
    mem = realloc(sub->sr_sub_ids, (sub->sr_sub_id_count + 1) * sizeof *sub->sr_sub_ids);
    SR_CHECK_MEM_RET(!mem, err_info);
    sub->sr_sub_ids = mem;

    /* prepare subscription options */
    sub_opts = SR_SUBSCR_PASSIVE | SR_SUBSCR_DONE_ONLY | (sub_no_thread ? SR_SUBSCR_NO_THREAD : 0);

    /* subscribe to the module */
    if (sr_module_change_subscribe(sess, ly_mod->name, sub->xpath_filter, srsn_yp_on_change_cb, sub, 0, sub_opts,
            &sub->sr_sub)) {
        err_info = sess->err_info;
        sess->err_info = NULL;
        return err_info;
    }

    /* add new sub ID */
    sub->sr_sub_ids[sub->sr_sub_id_count] = sr_subscription_get_last_sub_id(sub->sr_sub);
    ++sub->sr_sub_id_count;

    return NULL;
}

static int
srsn_ly_mod_has_data(const struct lys_module *mod, uint32_t config_mask)
{
    const struct lysc_node *root, *node;

    LY_LIST_FOR(mod->compiled->data, root) {
        LYSC_TREE_DFS_BEGIN(root, node) {
            if (node->flags & config_mask) {
                return 1;
            }

            LYSC_TREE_DFS_END(root, node);
        }
    }

    return 0;
}

/**
 * @brief Collect all modules with data selected by an XPath.
 *
 * @param[in] ly_ctx libyang context.
 * @param[in] xpath XPath filter.
 * @param[in] config_mask Config mask for relevant nodes.
 * @param[out] mod_set Set with all the relevant modules.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srsn_yp_sr_subscribe_filter_collect_mods(const struct ly_ctx *ly_ctx, const char *xpath, uint32_t config_mask,
        struct ly_set **mod_set)
{
    sr_error_info_t *err_info = NULL;
    const struct lys_module *ly_mod;
    const struct lysc_node *snode;
    struct ly_set *set = NULL;
    uint32_t i;

    /* learn what nodes are needed for evaluation */
    if (lys_find_xpath_atoms(ly_ctx, NULL, xpath, 0, &set)) {
        sr_errinfo_new_ly(&err_info, ly_ctx, NULL);
        goto cleanup;
    }

    /* allocate new set */
    if (ly_set_new(mod_set)) {
        sr_errinfo_new(&err_info, SR_ERR_LY, "%s", ly_errmsg(ly_ctx));
        goto cleanup;
    }

    /* add all the modules of the nodes */
    ly_mod = NULL;
    for (i = 0; i < set->count; ++i) {
        snode = set->snodes[i];

        /* skip uninteresting nodes */
        if ((snode->nodetype & (LYS_RPC | LYS_NOTIF)) || !(snode->flags & config_mask)) {
            continue;
        }

        if (snode->module == ly_mod) {
            /* skip already-added modules */
            continue;
        }
        ly_mod = snode->module;

        if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
            /* skip import-only modules, sysrepo, and ietf-netconf (as it has no data, only in libyang) */
            continue;
        }

        ly_set_add(*mod_set, (void *)ly_mod, 0, NULL);
    }

cleanup:
    ly_set_free(set, NULL);
    return err_info;
}

sr_error_info_t *
srsn_yp_sr_subscribe(sr_session_ctx_t *sess, struct srsn_sub *sub, int sub_no_thread)
{
    sr_error_info_t *err_info = NULL;
    const struct ly_ctx *ly_ctx;
    const struct lys_module *ly_mod;
    struct ly_set *mod_set = NULL;
    uint32_t idx, config_mask = (sub->ds == SR_DS_OPERATIONAL) ? LYS_CONFIG_MASK : LYS_CONFIG_W;

    ly_ctx = sr_session_acquire_context(sess);

    /* switch to the correct datastore */
    sr_session_switch_ds(sess, sub->ds);

    if (!sub->xpath_filter) {
        /* subscribe to all modules with (configuration) data */
        idx = 0;
        while ((ly_mod = ly_ctx_get_module_iter(ly_ctx, &idx))) {
            if (!ly_mod->implemented || !strcmp(ly_mod->name, "sysrepo") || !strcmp(ly_mod->name, "ietf-netconf")) {
                continue;
            }

            if (srsn_ly_mod_has_data(ly_mod, config_mask)) {
                /* subscribe to the module */
                if ((err_info = srsn_yp_sr_subscribe_mod(ly_mod, sess, sub_no_thread, sub))) {
                    goto cleanup;
                }
            }
        }
    } else {
        /* subscribe to all the relevant modules with the filter */
        if ((err_info = srsn_yp_sr_subscribe_filter_collect_mods(ly_ctx, sub->xpath_filter, config_mask, &mod_set))) {
            goto cleanup;
        }

        for (idx = 0; idx < mod_set->count; ++idx) {
            /* subscribe to the module */
            if ((err_info = srsn_yp_sr_subscribe_mod(mod_set->objs[idx], sess, sub_no_thread, sub))) {
                goto cleanup;
            }
        }
    }

cleanup:
    sr_session_release_context(sess);
    ly_set_free(mod_set, NULL);

    if (err_info) {
        for (idx = 0; idx < sub->sr_sub_id_count; ++idx) {
            sr_unsubscribe_sub(sub->sr_sub, sub->sr_sub_ids[idx]);
        }
        free(sub->sr_sub_ids);
        sub->sr_sub_ids = NULL;
        sub->sr_sub_id_count = 0;
    }
    return err_info;
}

sr_error_info_t *
srsn_yp_periodic_modify(struct srsn_sub *sub, uint32_t period_ms, const struct timespec *anchor_time)
{
    sr_error_info_t *err_info = NULL;

    if ((period_ms != sub->period_ms) || ((anchor_time && !sub->anchor_time.tv_sec) ||
            (!anchor_time && sub->anchor_time.tv_sec) || (anchor_time && sr_time_cmp(&sub->anchor_time, anchor_time)))) {
        /* update the timer */
        if ((err_info = srsn_yp_schedule_periodic_update(period_ms, anchor_time, sub, &sub->update_sntimer))) {
            goto cleanup;
        }

        /* update stored params */
        sub->period_ms = period_ms;
        if (anchor_time) {
            sub->anchor_time = *anchor_time;
        } else {
            sub->anchor_time.tv_sec = 0;
            sub->anchor_time.tv_nsec = 0;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
srsn_yp_on_change_modify(struct srsn_sub *sub, uint32_t dampening_period_ms)
{
    sr_error_info_t *err_info = NULL;
    struct timespec next_notif;

    if (dampening_period_ms != sub->dampening_period_ms) {
        if (!dampening_period_ms) {
            /* stop the timer */
            srsn_update_timer(NULL, NULL, &sub->damp_sntimer);

            /* send the prepared notification */
            if (sub->change_ntf && (err_info = srsn_yp_ntf_change_send(sub))) {
                goto cleanup;
            }
        } else if (sub->damp_sntimer.tid) {
            /* learn when the next notification is due */
            next_notif = sr_time_ts_add(&sub->last_notif, dampening_period_ms);

            /* update the timer */
            srsn_update_timer(&next_notif, NULL, &sub->damp_sntimer);
        }

        /* update stored params */
        sub->dampening_period_ms = dampening_period_ms;
    }

cleanup:
    return err_info;
}
