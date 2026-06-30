/**
 * @file notifd_config.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief sysrepo notification daemon configuration model and change handling
 *
 * @copyright
 * Copyright (c) 2026 CESNET, z.s.p.o.
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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "notifd.h"
#include "notifd_common.h"
#include "utils/subscribed_notifications.h"

#include <libyang/libyang.h>

/* forward declarations */
void receiver_destroy(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver);

/*
 * ---------------------------------------------------------------------------
 * Transport registry
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Static registry of all compiled-in transports.
 *
 * To add a new transport, define a notif_transport_ops_t in its own source
 * file and add a pointer to it here.
 */
static const notif_transport_ops_t *transport_registry[] = {
    &udp_transport_ops,
    NULL
};

/**
 * @brief Find a registered transport by its YANG identity value.
 *
 * @param[in] identity YANG identity string (e.g. "ietf-udp-notif-transport:udp-notif").
 * @return Pointer to the matching transport ops, or NULL if not found.
 */
const notif_transport_ops_t *
notif_transport_find_by_identity(const char *identity)
{
    int i;

    if (!identity) {
        return NULL;
    }

    for (i = 0; transport_registry[i]; i++) {
        if (!strcmp(transport_registry[i]->transport_identity, identity)) {
            return transport_registry[i];
        }
    }

    return NULL;
}

/**
 * @brief Find a registered transport by its NP container name.
 *
 * @param[in] container_name NP container node name (e.g. "udp-notif-receiver").
 * @return Pointer to the matching transport ops, or NULL if not found.
 */
const notif_transport_ops_t *
notif_transport_find_by_container(const char *container_name)
{
    int i;

    if (!container_name) {
        return NULL;
    }

    for (i = 0; transport_registry[i]; i++) {
        if (!strcmp(transport_registry[i]->config_container_name, container_name)) {
            return transport_registry[i];
        }
    }

    return NULL;
}

/*
 * ---------------------------------------------------------------------------
 * Helpers
 * ---------------------------------------------------------------------------
 */

int
get_descendant_mandatory(const struct lyd_node *ctx_node, const char *path, struct lyd_node **match)
{
    *match = NULL;

    lyd_find_path(ctx_node, path, 0, match);

    if (!*match) {
        SRNTF_LOG_ERR("Expected descendant \"%s\" of node \"%s\" missing.", path, LYD_NAME(ctx_node));
        return SR_ERR_NOT_FOUND;
    }
    return SR_ERR_OK;
}

void
get_descendant_optional(const struct lyd_node *ctx_node, const char *path, struct lyd_node **match)
{
    uint32_t ll = 0;

    *match = NULL;

    /* temporarily suppress error logging, since the node may be legitimately missing */
    ly_temp_log_options(&ll);

    lyd_find_path(ctx_node, path, 0, match);

    /* restore error logging */
    ly_temp_log_options(NULL);
}

const char *
subscription_state2str(notif_sub_state_t state)
{
    switch (state) {
    case NOTIF_SUB_STATE_VALID:
        return "valid";
    case NOTIF_SUB_STATE_INVALID:
        return "invalid";
    case NOTIF_SUB_STATE_CONCLUDED:
        return "concluded";
    default:
        return "unknown";
    }
}

const char *
receiver_state2str(notif_recv_state_t state)
{
    switch (state) {
    case NOTIF_RECV_STATE_ACTIVE:
        return "active";
    case NOTIF_RECV_STATE_SUSPENDED:
        return "suspended";
    case NOTIF_RECV_STATE_CONNECTING:
        return "connecting";
    case NOTIF_RECV_STATE_DISCONNECTED:
        return "disconnected";
    default:
        return "unknown";
    }
}

static int
notif_encoding_parse(const struct lyd_node *node, notif_encoding_t *encoding)
{
    int rc = SR_ERR_OK;
    const char *value;

    *encoding = NOTIF_ENCODING_UNSET;

    value = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(value, "encode-xml")) {
        *encoding = NOTIF_ENCODING_XML;
    } else if (!strcmp(value, "encode-json")) {
        *encoding = NOTIF_ENCODING_JSON;
    } else if (!strcmp(value, "encode-cbor")) {
        SRNTF_LOG_ERR("CBOR encoding is not yet supported.");
        rc = SR_ERR_UNSUPPORTED;
    } else {
        SRNTF_LOG_ERR("Unsupported encoding \"%s\".", value);
        rc = SR_ERR_UNSUPPORTED;
    }

    return rc;
}

static int
stream_filter_xpath_get(sr_session_ctx_t *sess, const char *filter_name, char **xpath_filter)
{
    int rc = SR_ERR_OK;
    struct lyd_node *filter, *tree;
    char *path = NULL;
    sr_data_t *data = NULL;

    /* get the filter with this name */
    if ((asprintf(&path, "/ietf-subscribed-notifications:filters/stream-filter[name=\"%s\"]", filter_name) == -1)) {
        rc = SR_ERR_NO_MEMORY;
        ERRMEM;
        goto cleanup;
    }
    if ((rc = sr_get_data(sess, path, 0, 0, 0, &data))) {
        goto cleanup;
    }
    if (!data) {
        /* filter not set yet, so no filter to apply */
        goto cleanup;
    }

    /* data->tree points to filters cont, we go one level down to the filter instance */
    tree = lyd_child(data->tree);

    /* because it's a choice, only one of the two filter types can be present */
    get_descendant_optional(tree, "stream-subtree-filter", &filter);
    if (filter) {
        /* convert the subtree filter to an xpath filter, subtree is anydata so use lyd_child_any */
        if ((rc = srsn_filter_subtree2xpath(lyd_child_any(filter), sess, xpath_filter))) {
            goto cleanup;
        }
    }

    get_descendant_optional(tree, "stream-xpath-filter", &filter);
    if (filter) {
        /* filter is already an xpath filter, just return the value */
        *xpath_filter = strdup(lyd_get_value(filter));
        CHECK_ERRMEM_GOTO(*xpath_filter, rc, cleanup);
    }

cleanup:
    free(path);
    sr_release_data(data);
    return rc;
}

/**
 * @brief Check whether the specified stream supports replay.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] stream Name of the stream to check.
 * @param[in] xpath_filter Optional stream filter to consider when determining replay support.
 * @param[out] earliest_replay_start_time If replay is supported,
 * set to the earliest replay start time across all modules in the stream.
 * @return ::SR_ERR_OK if replay is supported, ::SR_ERR_UNSUPPORTED if not, or other error code on failure.
 */
static int
stream_supports_replay(notifd_ctx_t *notifd_ctx, const char *stream, const char *xpath_filter,
        struct timespec *earliest_replay_start_time)
{
    int rc = SR_ERR_OK, r, replay_enabled = 0;
    const struct ly_ctx *ly_ctx;
    struct ly_set *mod_set = NULL;
    uint32_t i;
    const struct lys_module *ly_mod;
    sr_conn_ctx_t *conn;
    struct timespec ts = {0};

    if (!earliest_replay_start_time) {
        return SR_ERR_INVAL_ARG;
    }

    earliest_replay_start_time->tv_sec = 0;
    earliest_replay_start_time->tv_nsec = 0;

    conn = sr_session_get_connection(notifd_ctx->sr_sess);
    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);

    if ((rc = srsn_stream_collect_mods(stream, xpath_filter, ly_ctx, &mod_set))) {
        goto cleanup;
    }

    for (i = 0; i < mod_set->count; i++) {
        ly_mod = mod_set->objs[i];

        /* get earliest replay start time */
        if ((rc = sr_get_module_replay_support(conn, ly_mod->name, NULL, &r))) {
            goto cleanup;
        }

        if (!r) {
            SRNTF_LOG_WRN("Module \"%s\" in stream \"%s\" does not support replay.", ly_mod->name, stream);
            continue;
        }

        if ((rc = sr_get_module_replay_start(conn, ly_mod->name, NULL, NULL, &ts))) {
            goto cleanup;
        }

        replay_enabled = 1;

        if (((earliest_replay_start_time->tv_sec == 0) && (earliest_replay_start_time->tv_nsec == 0)) ||
                ((ts.tv_sec || ts.tv_nsec) &&
                (timespec_cmp(&ts, earliest_replay_start_time) < 0))) {
            *earliest_replay_start_time = ts;
        }
    }

    if (!replay_enabled) {
        rc = SR_ERR_UNSUPPORTED;
    }

cleanup:
    sr_session_release_context(notifd_ctx->sr_sess);
    ly_set_free(mod_set, NULL);
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Find functions
 * ---------------------------------------------------------------------------
 */

notif_sub_t *
subscription_find_by_id(notifd_ctx_t *ctx, uint32_t sub_id)
{
    LY_ARRAY_COUNT_TYPE i;

    LY_ARRAY_FOR(ctx->subs, i) {
        if (ctx->subs[i]->id == sub_id) {
            return ctx->subs[i];
        }
    }

    return NULL;
}

notif_receiver_t *
receiver_find_by_name(notif_sub_t *sub, const char *name)
{
    LY_ARRAY_COUNT_TYPE i;

    LY_ARRAY_FOR(sub->receivers, i) {
        if (!strcmp(sub->receivers[i].name, name)) {
            return &sub->receivers[i];
        }
    }
    return NULL;
}

notif_receiver_inst_t *
receiver_inst_find_by_name(notifd_ctx_t *ctx, const char *name)
{
    LY_ARRAY_COUNT_TYPE i;

    LY_ARRAY_FOR(ctx->recv_insts, i) {
        if (!strcmp(ctx->recv_insts[i]->name, name)) {
            return ctx->recv_insts[i];
        }
    }

    return NULL;
}

notif_sub_t *
subscription_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node)
{
    uint32_t sub_id;
    struct lyd_node *n;

    /* find the ancestor subscription node */
    while (ctx_node) {
        if (!strcmp(LYD_NAME(ctx_node), "subscription")) {
            break;
        }
        ctx_node = lyd_parent(ctx_node);
    }
    if (!ctx_node) {
        return NULL;
    }

    /* get subscription ID */
    if (get_descendant_mandatory(ctx_node, "id", &n)) {
        return NULL;
    }
    sub_id = (uint32_t)strtoul(lyd_get_value(n), NULL, 10);

    return subscription_find_by_id(notifd_ctx, sub_id);
}

notif_receiver_t *
receiver_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node)
{
    const char *name;
    struct lyd_node *n;
    notif_sub_t *sub;

    /* find the ancestor receiver node */
    while (ctx_node) {
        if (!strcmp(LYD_NAME(ctx_node), "receiver")) {
            break;
        }
        ctx_node = lyd_parent(ctx_node);
    }
    if (!ctx_node) {
        return NULL;
    }

    /* get receiver name */
    if (get_descendant_mandatory(ctx_node, "name", &n)) {
        return NULL;
    }
    name = lyd_get_value(n);

    /* find the ancestor subscription node */
    if (!(sub = subscription_find_by_node(notifd_ctx, ctx_node))) {
        return NULL;
    }

    return receiver_find_by_name(sub, name);
}

notif_receiver_inst_t *
receiver_inst_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node)
{
    const char *name;
    struct lyd_node *n;

    /* find the ancestor receiver-instance node */
    while (ctx_node) {
        if (!strcmp(LYD_NAME(ctx_node), "receiver-instance")) {
            break;
        }
        ctx_node = lyd_parent(ctx_node);
    }
    if (!ctx_node) {
        return NULL;
    }

    /* get receiver-instance name */
    if (get_descendant_mandatory(ctx_node, "name", &n)) {
        return NULL;
    }
    name = lyd_get_value(n);

    return receiver_inst_find_by_name(notifd_ctx, name);
}

/*
 * ---------------------------------------------------------------------------
 * Subscription field change handlers
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Mark a subscription as invalid, setting the reason if not already set.
 *
 * @param[in] sub Subscription to mark as invalid.
 * @param[in] reason Optional YANG identity-ref reason for invalidity.
 */
static void
sub_invalidate(notif_sub_t *sub, const char *reason)
{
    sub->state = NOTIF_SUB_STATE_INVALID;
    if (!sub->modif_err_reason) {
        sub->modif_err_reason = reason ? reason : "ietf-subscribed-notifications:no-such-subscription";
    }
}

int
handle_stream(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* mandatory leaf, cr + del handled by 'subscription', so only handle mod */
    if (op == SR_OP_MODIFIED) {
        /* switch to the new value */
        free(sub->stream);
        sub->stream = strdup(lyd_get_value(node));
        if (!sub->stream) {
            rc = SR_ERR_NO_MEMORY;
            ERRMEM;
            goto cleanup;
        }

        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_stream_filter_name(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* free the old filter */
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;
        free(sub->filter_ref);
        sub->filter_ref = NULL;

        /* dup the referenced filter name */
        sub->filter_ref = strdup(lyd_get_value(node));
        CHECK_ERRMEM_GOTO(sub->filter_ref, rc, cleanup);

        /* get the xpath filter from the referenced stream filter */
        if ((rc = stream_filter_xpath_get(notifd_ctx->sr_sess, sub->filter_ref, &sub->xpath_filter))) {
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        /* just reset all filter info */
        free(sub->filter_ref);
        sub->filter_ref = NULL;
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_stream_subtree_filter(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;
    struct lyd_node *filter;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* free the old filter */
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;

        /* get the first child of the anydata stream-subtree-filter node, which is the first actual filter sibling */
        filter = lyd_child_any(node);
        if (filter) {
            /* filter exists, convert it to an xpath filter and switch to the new value */
            if ((rc = srsn_filter_subtree2xpath(filter, notifd_ctx->sr_sess, &sub->xpath_filter))) {
                goto cleanup;
            }
        }
    } else if (op == SR_OP_DELETED) {
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_stream_xpath_filter(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* switch to the new value */
        free(sub->xpath_filter);
        sub->xpath_filter = strdup(lyd_get_value(node));
        if (!sub->xpath_filter) {
            rc = SR_ERR_NO_MEMORY;
            ERRMEM;
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_encoding(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* switch to the new value */
        if ((rc = notif_encoding_parse(node, &sub->encoding))) {
            sub->modif_err_reason = "ietf-subscribed-notifications:no-such-subscription";
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        sub->encoding = NOTIF_ENCODING_UNSET;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_stop_time(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* switch to the new value */
        if (ly_time_str2ts(lyd_get_value(node), &sub->stop_time)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        /* clear stop time */
        sub->stop_time.tv_sec = 0;
        sub->stop_time.tv_nsec = 0;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_configured_replay(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *UNUSED(node), sr_change_oper_t op)
{
    int rc = SR_ERR_OK;
    struct timespec replay_start_time = {0};

    /* optional leaf, type empty, so only handle create and delete */
    if (op == SR_OP_CREATED) {
        /* switch to the new value */
        sub->replay = 1;
    } else if (op == SR_OP_DELETED) {
        /* clear replay */
        sub->replay = 0;
        sub->start_time.tv_sec = 0;
        sub->start_time.tv_nsec = 0;
    }

    if (op == SR_OP_CREATED) {
        /* we need to check that at least 1 mod in the stream supports replay, otherwise this is an invalid subscription config */
        if ((rc = stream_supports_replay(notifd_ctx, sub->stream, sub->xpath_filter, &replay_start_time))) {
            SRNTF_LOG_ERR("Stream \"%s\" does not support replay, cannot enable replay for subscription ID %" PRIu32 ".",
                    sub->stream, sub->id);
            sub->modif_err_reason = "ietf-subscribed-notifications:stream-unavailable";
            goto cleanup;
        }

        sub->start_time = replay_start_time;

        /* mark sub as modified so we know to send subscription-modified notification + resubscribe to apply replay */
        sub->modified = 1;
        sub->resubscribe = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_purpose(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* switch to the new value */
        free(sub->purpose);
        sub->purpose = strdup(lyd_get_value(node));
        if (!sub->purpose) {
            rc = SR_ERR_NO_MEMORY;
            ERRMEM;
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        /* clear purpose */
        free(sub->purpose);
        sub->purpose = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

int
handle_source_address(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;
    notif_receiver_t *receiver;
    LY_ARRAY_COUNT_TYPE i, j, count;

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* switch to the new value */
        free(sub->local_address);
        sub->local_address = strdup(lyd_get_value(node));
        if (!sub->local_address) {
            rc = SR_ERR_NO_MEMORY;
            ERRMEM;
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        /* clear local address */
        free(sub->local_address);
        sub->local_address = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        /* reconnect all the receivers, since we will need to create new sockets with the new local address */
        count = LY_ARRAY_COUNT(sub->receivers);
        for (i = 0; i < count; i++) {
            receiver = &sub->receivers[i];
            if (!receiver->inst) {
                /* receiver instance not mandatory */
                continue;
            }

            rc = notif_receiver_reconnect(notifd_ctx, sub, receiver, NULL);
            if (rc) {
                /* rollback: disconnect previously reconnected receivers so they are in a consistent state */
                for (j = 0; j < i; j++) {
                    if (sub->receivers[j].inst && notif_receiver_is_connected(&sub->receivers[j])) {
                        notif_receiver_disconnect(&sub->receivers[j]);
                        sub->receivers[j].state = NOTIF_RECV_STATE_DISCONNECTED;
                    }
                }
                goto cleanup;
            }
        }

        /* mark sub as modified so we know to send subscription-modified notification */
        sub->modified = 1;
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
    }
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Receiver-instance config change dispatch
 * ---------------------------------------------------------------------------
 */

int
receiver_inst_config_change(notif_receiver_inst_t *recv_inst, const struct lyd_node *node, sr_change_oper_t op)
{
    const char *node_name;
    const notif_transport_ops_t *ops;

    node_name = LYD_NAME(node);

    if (recv_inst->ops) {
        return recv_inst->ops->config_change(recv_inst, node, op);
    }

    ops = notif_transport_find_by_container(node_name);
    if (ops) {
        recv_inst->ops = ops;
        recv_inst->type = ops->type;
        return ops->config_change(recv_inst, node, op);
    }

    return SR_ERR_OK;
}

int
handle_receiver_instance_ref(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;
    notif_receiver_t *receiver;
    notif_receiver_inst_t *new_inst;

    /* get the receiver */
    if (!(receiver = receiver_find_by_node(notifd_ctx, node))) {
        SRNTF_LOG_ERR("Failed to find receiver for receiver-instance-ref change.");
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* optional leaf, need to handle all but move */
    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
        /* get the new instance */
        new_inst = receiver_inst_find_by_name(notifd_ctx, lyd_get_value(node));
        if (!new_inst) {
            SRNTF_LOG_ERR("Receiver instance \"%s\" not found for receiver \"%s\".", lyd_get_value(node), receiver->name);
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }
    } else if (op == SR_OP_DELETED) {
        /* the instance ref is being removed */
        new_inst = NULL;
    }

    if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED) || (op == SR_OP_DELETED)) {
        if (!new_inst) {
            /* just disconnect the old instance */
            notif_receiver_disconnect(receiver);
            receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
            receiver->inst = NULL;
            receiver->ops = NULL;
        } else {
            /* disconnect from old and connect to the new instance */
            rc = notif_receiver_reconnect(notifd_ctx, sub, receiver, new_inst);
            if (rc) {
                goto cleanup;
            }
        }
    }

cleanup:
    if (rc) {
        sub_invalidate(sub, NULL);
        sub->modified = 1;
    }
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Subscription parsing and CRUD
 * ---------------------------------------------------------------------------
 */

static int
subscription_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node, notif_sub_t *sub)
{
    int rc = SR_ERR_OK;
    struct lyd_node *n, *filter;
    struct ly_set *set = NULL;
    uint32_t i;

    /* subscription ID */
    if ((rc = get_descendant_mandatory(node, "id", &n))) {
        goto cleanup;
    }
    sub->id = strtoul(lyd_get_value(n), NULL, 10);

    /* stream */
    if ((rc = get_descendant_mandatory(node, "stream", &n))) {
        goto cleanup;
    }
    sub->stream = strdup(lyd_get_value(n));
    CHECK_ERRMEM_GOTO(sub->stream, rc, cleanup);

    /* stream-filter-name */
    get_descendant_optional(node, "stream-filter-name", &n);
    if (n) {
        /* dup the referenced filter name */
        sub->filter_ref = strdup(lyd_get_value(n));
        CHECK_ERRMEM_GOTO(sub->filter_ref, rc, cleanup);

        /* get the xpath filter from the referenced stream filter (if any, it's a leafref, not instanceref) */
        if ((rc = stream_filter_xpath_get(notifd_ctx->sr_sess, sub->filter_ref, &sub->xpath_filter))) {
            goto cleanup;
        }
    }

    /* subtree filter */
    get_descendant_optional(node, "stream-subtree-filter", &n);
    if (n) {
        /* free the old filter */
        free(sub->xpath_filter);
        sub->xpath_filter = NULL;

        /* get the first child of the anydata stream-subtree-filter node, which is the first actual filter sibling */
        filter = lyd_child_any(n);
        if (filter) {
            /* filter exists, convert it to an xpath filter and switch to the new value */
            if ((rc = srsn_filter_subtree2xpath(filter, notifd_ctx->sr_sess, &sub->xpath_filter))) {
                goto cleanup;
            }
        }
    }

    /* xpath filter */
    get_descendant_optional(node, "stream-xpath-filter", &n);
    if (n) {
        sub->xpath_filter = strdup(lyd_get_value(n));
        CHECK_ERRMEM_GOTO(sub->xpath_filter, rc, cleanup);
    }

    /* encoding */
    get_descendant_optional(node, "encoding", &n);
    if (n) {
        if ((rc = notif_encoding_parse(n, &sub->encoding))) {
            goto cleanup;
        }
    }

    /* stop time */
    get_descendant_optional(node, "stop-time", &n);
    if (n) {
        if (ly_time_str2ts(lyd_get_value(n), &sub->stop_time)) {
            rc = SR_ERR_LY;
            goto cleanup;
        }
    }

    /* transport (mandatory for configured subs, even though it is not mandatory in the model), refine "transport" */
    if ((rc = get_descendant_mandatory(node, "transport", &n))) {
        goto cleanup;
    }
    if (!notif_transport_find_by_identity(lyd_get_value(n))) {
        SRNTF_LOG_ERR("Unsupported transport \"%s\".", lyd_get_value(n));
        rc = SR_ERR_UNSUPPORTED;
        goto cleanup;
    }

    /* purpose */
    get_descendant_optional(node, "purpose", &n);
    if (n) {
        sub->purpose = strdup(lyd_get_value(n));
        CHECK_ERRMEM_GOTO(sub->purpose, rc, cleanup);
    }

    /* source address */
    get_descendant_optional(node, "source-address", &n);
    if (n) {
        sub->local_address = strdup(lyd_get_value(n));
        CHECK_ERRMEM_GOTO(sub->local_address, rc, cleanup);
    }

    /* receivers */
    if (lyd_find_xpath(node, "receivers/receiver", &set)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }
    for (i = 0; i < set->count; i++) {
        if ((rc = receiver_create_from_node(notifd_ctx, sub, set->dnodes[i]))) {
            goto cleanup;
        }
    }

cleanup:
    ly_set_free(set, NULL);
    return rc;
}

/**
 * @brief Disconnect all receivers of a subscription.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription whose receivers should be disconnected.
 */
static void
subscription_receivers_disconnect(notifd_ctx_t *notifd_ctx, notif_sub_t *sub)
{
    notif_receiver_t *receiver;

    LY_ARRAY_FOR(sub->receivers, notif_receiver_t, receiver) {
        /* disconnect the receiver */
        notification_dispatch_stop(notifd_ctx, receiver);
        notif_receiver_disconnect(receiver);
    }
}

int
subscription_create_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node)
{
    int rc = SR_ERR_OK;
    notif_sub_t *sub, **sub_ptr = NULL;

    /* create a new sub and add it to the context array */
    sub = calloc(1, sizeof *sub);
    CHECK_ERRMEM_RET(sub);
    LY_ARRAY_NEW_GOTO(LYD_CTX(node), notifd_ctx->subs, sub_ptr, rc, cleanup);
    *sub_ptr = sub;
    sub->state = NOTIF_SUB_STATE_VALID;

    /* parse the subscription */
    if ((rc = subscription_from_node(notifd_ctx, node, sub))) {
        goto cleanup;
    }

cleanup:
    if (rc) {
        subscription_receivers_disconnect(notifd_ctx, sub);
        sub_invalidate(sub, NULL);
        if (!sub_ptr) {
            free(sub);
        }
    }
    return rc;
}

/**
 * @brief Destroy a subscription, disconnecting all receivers and removing it from the context.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription to destroy.
 */
static void
subscription_destroy(notifd_ctx_t *notifd_ctx, notif_sub_t *sub)
{
    LY_ARRAY_COUNT_TYPE i;

    if (!sub) {
        return;
    }

    /* free members */
    free(sub->stream);
    free(sub->xpath_filter);
    free(sub->filter_ref);
    free(sub->purpose);
    free(sub->local_address);
    for (i = LY_ARRAY_COUNT(sub->receivers); i > 0; i--) {
        receiver_destroy(notifd_ctx, sub, &sub->receivers[i - 1]);
    }
    LY_ARRAY_FREE(sub->receivers);

    /* replace with the last and decrement array */
    LY_ARRAY_FOR(notifd_ctx->subs, i) {
        if (notifd_ctx->subs[i] == sub) {
            notifd_ctx->subs[i] = notifd_ctx->subs[LY_ARRAY_COUNT(notifd_ctx->subs) - 1];
            break;
        }
    }
    LY_ARRAY_DECREMENT_FREE(notifd_ctx->subs);
    free(sub);
}

int
subscription_destroy_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node)
{
    notif_sub_t *sub;

    /* try to find the sub */
    if (!(sub = subscription_find_by_node(notifd_ctx, node))) {
        SRNTF_LOG_ERR("Failed to find subscription \"%s\" for destruction.", lyd_get_value(lyd_child(node)));
        return SR_ERR_NOT_FOUND;
    }

    /* if the sub is still valid, send subscription-terminated notification to all receivers */
    if (sub->state == NOTIF_SUB_STATE_VALID) {
        subscription_terminated_notif_send(notifd_ctx, sub, NULL, "ietf-subscribed-notifications:no-such-subscription");
        sub->state = NOTIF_SUB_STATE_CONCLUDED;
    }

    /* destroy the sub */
    subscription_destroy(notifd_ctx, sub);

    return SR_ERR_OK;
}

/*
 * ---------------------------------------------------------------------------
 * Receiver parsing and CRUD
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Parse a receiver from a lyd_node into a notif_receiver_t struct.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] node receiver node.
 * @param[out] receiver Parsed receiver struct.
 * @return SR_ERR_OK on success, or other error code on failure.
 */
static int
receiver_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node, notif_receiver_t *receiver)
{
    int rc = SR_ERR_OK;
    struct lyd_node *n;

    /* receiver name */
    if ((rc = get_descendant_mandatory(node, "name", &n))) {
        goto cleanup;
    }
    receiver->name = strdup(lyd_get_value(n));
    CHECK_ERRMEM_GOTO(receiver->name, rc, cleanup);

    /* recv instance ref */
    get_descendant_optional(node, "ietf-subscribed-notif-receivers:receiver-instance-ref", &n);
    if (n) {
        receiver->inst = receiver_inst_find_by_name(notifd_ctx, lyd_get_value(n));
        if (!receiver->inst) {
            SRNTF_LOG_ERR("Receiver instance \"%s\" not found for receiver \"%s\".", lyd_get_value(n), receiver->name);
            rc = SR_ERR_NOT_FOUND;
            goto cleanup;
        }
        receiver->ops = receiver->inst->ops;
    }

cleanup:
    return rc;
}

int
receiver_create_from_node(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node)
{
    int rc = SR_ERR_OK, r;
    notif_receiver_t *receiver;

    /* create a new receiver */
    LY_ARRAY_NEW_GOTO(LYD_CTX(node), sub->receivers, receiver, rc, cleanup);
    receiver->srsn_data.fd = -1;
    receiver->sub = sub;

    /* parse it */
    if ((rc = receiver_from_node(notifd_ctx, node, receiver))) {
        goto cleanup;
    }

    /* start dispatch so this receiver can receive notifications */
    if ((rc = notification_dispatch_start(notifd_ctx, sub, receiver))) {
        goto cleanup;
    }

    /* connect the receiver and send subscription-started */
    receiver->state = NOTIF_RECV_STATE_CONNECTING;
    r = notif_receiver_connect(receiver);

    if (!r && (sub->state == NOTIF_SUB_STATE_VALID)) {
        r = subscription_started_notif_send(notifd_ctx, sub, receiver);
        if (!r) {
            /* successfully sent, receiver is now active */
            receiver->state = NOTIF_RECV_STATE_ACTIVE;
        } else {
            /* on failure, receiver is now disconnected */
            notif_receiver_disconnect(receiver);
            receiver->state = NOTIF_RECV_STATE_DISCONNECTED;
        }
    }

cleanup:
    return rc;
}

void
receiver_destroy(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver)
{
    if (!sub || !receiver) {
        return;
    }

    /* stop dispatch for this receiver */
    notification_dispatch_stop(notifd_ctx, receiver);

    /* disconnect the receiver */
    notif_receiver_disconnect(receiver);

    /* free members */
    free(receiver->name);
    receiver->inst = NULL;

    /* replace with the last and decrement array */
    *receiver = sub->receivers[LY_ARRAY_COUNT(sub->receivers) - 1];
    LY_ARRAY_DECREMENT_FREE(sub->receivers);
}

int
receiver_destroy_from_node(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node)
{
    int rc = SR_ERR_OK;
    notif_receiver_t *receiver;

    /* find the receiver */
    if (!(receiver = receiver_find_by_node(notifd_ctx, node))) {
        SRNTF_LOG_ERR("Receiver with name \"%s\" not found for deletion.", lyd_get_value(lyd_child(node)));
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    /* if the receiver is active, send subscription-terminated to it */
    if (receiver->state == NOTIF_RECV_STATE_ACTIVE) {
        subscription_terminated_notif_send(notifd_ctx, sub, receiver, "ietf-subscribed-notifications:no-such-subscription");
    }

    /* destroy the receiver */
    receiver_destroy(notifd_ctx, sub, receiver);

cleanup:
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Receiver-instance parsing and CRUD
 * ---------------------------------------------------------------------------
 */

static int
receiver_instance_from_node(const struct lyd_node *node, notif_receiver_inst_t *recv_inst)
{
    int rc = SR_ERR_OK;
    struct lyd_node *n;
    struct lyd_node *child;
    const notif_transport_ops_t *ops;

    /* receiver instance name */
    if ((rc = get_descendant_mandatory(node, "name", &n))) {
        goto cleanup;
    }
    recv_inst->name = strdup(lyd_get_value(n));
    CHECK_ERRMEM_GOTO(recv_inst->name, rc, cleanup);

    /* find the transport config container by iterating children */
    LY_LIST_FOR(lyd_child(node), child) {
        ops = notif_transport_find_by_container(LYD_NAME(child));
        if (ops) {
            recv_inst->type = ops->type;
            recv_inst->ops = ops;

            if ((rc = ops->config_parse(child, &recv_inst->transport_config))) {
                goto cleanup;
            }
            break;
        }
    }

cleanup:
    return rc;
}

int
receiver_instance_create_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node)
{
    int rc = SR_ERR_OK;
    notif_receiver_inst_t *recv_inst, **recv_inst_ptr;

    /* create a new receiver instance and add it to the context array */
    LY_ARRAY_NEW_GOTO(LYD_CTX(node), notifd_ctx->recv_insts, recv_inst_ptr, rc, cleanup);
    recv_inst = calloc(1, sizeof *recv_inst);
    CHECK_ERRMEM_GOTO(recv_inst, rc, cleanup);
    *recv_inst_ptr = recv_inst;

    /* parse the receiver instance */
    if ((rc = receiver_instance_from_node(node, recv_inst))) {
        goto cleanup;
    }

cleanup:
    return rc;
}

static void
receiver_instance_destroy(notifd_ctx_t *notifd_ctx, notif_receiver_inst_t *recv_inst)
{
    LY_ARRAY_COUNT_TYPE i;

    if (!recv_inst) {
        return;
    }

    /* free members */
    free(recv_inst->name);
    if (recv_inst->ops && recv_inst->transport_config) {
        recv_inst->ops->config_destroy(recv_inst->transport_config);
        recv_inst->transport_config = NULL;
    }
    recv_inst->ops = NULL;

    /* replace with the last and decrement array */
    LY_ARRAY_FOR(notifd_ctx->recv_insts, i) {
        if (notifd_ctx->recv_insts[i] == recv_inst) {
            notifd_ctx->recv_insts[i] = notifd_ctx->recv_insts[LY_ARRAY_COUNT(notifd_ctx->recv_insts) - 1];
            break;
        }
    }
    LY_ARRAY_DECREMENT_FREE(notifd_ctx->recv_insts);
    free(recv_inst);
}

int
receiver_instance_destroy_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node)
{
    notif_receiver_inst_t *recv_inst;

    /* find the receiver instance */
    if (!(recv_inst = receiver_inst_find_by_node(notifd_ctx, node))) {
        SRNTF_LOG_ERR("Receiver instance with name \"%s\" not found for deletion.", lyd_get_value(lyd_child(node)));
        return SR_ERR_NOT_FOUND;
    }

    /* destroy the receiver instance, no need to lock as no subs can point to it anymore */
    receiver_instance_destroy(notifd_ctx, recv_inst);
    return SR_ERR_OK;
}

/*
 * ---------------------------------------------------------------------------
 * Post-processing after config changes
 * ---------------------------------------------------------------------------
 */

int
subscription_resubscribe(notifd_ctx_t *notifd_ctx, notif_sub_t *sub)
{
    int rc = SR_ERR_OK;
    notif_receiver_t *receiver;

    LY_ARRAY_FOR(sub->receivers, notif_receiver_t, receiver) {
        /* stop the dispatch, which will unsubscribe from sysrepo and stop all timers */
        notification_dispatch_stop(notifd_ctx, receiver);

        /* start the dispatch again with the new params, which will resubscribe to sysrepo and restart timers */
        if ((rc = notification_dispatch_start(notifd_ctx, sub, receiver))) {
            goto cleanup;
        }
    }

 cleanup:
    return rc;
}

void
process_modified_subscriptions(notifd_ctx_t *notifd_ctx)
{
    int r;
    notif_sub_t **sub;

    /* go through all subs and send subscription-modified for those that are modified */
    LY_ARRAY_FOR(notifd_ctx->subs, notif_sub_t *, sub) {
        if ((*sub)->resubscribe) {
            r = subscription_resubscribe(notifd_ctx, *sub);
            if (!r) {
                (*sub)->state = NOTIF_SUB_STATE_VALID;
            } else {
                sub_invalidate(*sub, NULL);
            }

            (*sub)->resubscribe = 0;
        }

        if ((*sub)->modified || (*sub)->modif_err_reason) {
            if ((*sub)->state == NOTIF_SUB_STATE_VALID) {
                /* valid modification => subscription-modified */
                subscription_modified_notif_send(notifd_ctx, *sub, NULL);
            } else if ((*sub)->state == NOTIF_SUB_STATE_INVALID) {
                /* invalid modification => subscription-modified with reason + subscription-terminated */
                subscription_terminated_notif_send(notifd_ctx, *sub, NULL, (*sub)->modif_err_reason);
            }

            /* reset modified flag and error reason */
            (*sub)->modified = 0;
            (*sub)->modif_err_reason = NULL;
        }
    }
}

void
process_modified_receiver_instances(notifd_ctx_t *notifd_ctx)
{
    notif_receiver_inst_t **recv_inst;
    notif_sub_t **sub;
    notif_receiver_t *receiver;

    /* go through all receiver instances and reconnect those that are modified */
    LY_ARRAY_FOR(notifd_ctx->recv_insts, notif_receiver_inst_t *, recv_inst) {
        if (!(*recv_inst)->modified) {
            /* if not modified, skip */
            continue;
        }

        /* reconnect all referencing receivers */
        LY_ARRAY_FOR(notifd_ctx->subs, notif_sub_t *, sub) {
            LY_ARRAY_FOR((*sub)->receivers, notif_receiver_t, receiver) {
                if (receiver->inst == *recv_inst) {
                    notif_receiver_reconnect(notifd_ctx, *sub, receiver, NULL);
                }
            }
        }

        /* reset modified flag */
        (*recv_inst)->modified = 0;
    }
}

/*
 * ---------------------------------------------------------------------------
 * Filter change handler (used by filter_change_cb)
 * ---------------------------------------------------------------------------
 */

int
handle_stream_filter(notifd_ctx_t *notifd_ctx, const struct lyd_node *node, int is_subtree)
{
    int rc = SR_ERR_OK, r;
    const char *filter_inst_name = NULL;
    notif_sub_t **sub;
    struct lyd_node *filter_inst_name_node;
    char *new_filter = NULL;

    /* get the key of the filter instance list, by which the subs reference this filter */
    if ((rc = get_descendant_mandatory(lyd_parent(node), "name", &filter_inst_name_node))) {
        return rc;
    }
    filter_inst_name = lyd_get_value(filter_inst_name_node);

    /* find the sub(s) that reference this filter and update their xpath_filter */
    LY_ARRAY_FOR(notifd_ctx->subs, notif_sub_t *, sub) {
        r = 0;
        if ((*sub)->filter_ref && !strcmp((*sub)->filter_ref, filter_inst_name)) {
            /* match */
            if (is_subtree) {
                /* subtree filter reference, convert to xpath, subtree is anydata, so use lyd_child_any() to get it */
                if ((r = srsn_filter_subtree2xpath(lyd_child_any(node), notifd_ctx->sr_sess, &new_filter))) {
                    (*sub)->modif_err_reason = "ietf-subscribed-notifications:no-such-subscription";
                    rc = r;
                }
            } else {
                /* xpath filter reference, just dup the value */
                new_filter = strdup(lyd_get_value(node));
                if (!new_filter) {
                    r = rc = SR_ERR_NO_MEMORY;
                    (*sub)->modif_err_reason = "ietf-subscribed-notifications:no-such-subscription";
                }
            }

            if (r) {
                /* we failed to convert the filter, err reason was set */
                continue;
            }

            if ((!new_filter && (*sub)->xpath_filter) || (new_filter && !(*sub)->xpath_filter) ||
                    (new_filter && (*sub)->xpath_filter && strcmp(new_filter, (*sub)->xpath_filter))) {
                /* the filter was actually modified, update it and mark the sub for resubscription */
                free((*sub)->xpath_filter);
                (*sub)->xpath_filter = new_filter;
                (*sub)->modified = 1;
                (*sub)->resubscribe = 1;
            } else {
                /* the filter was not actually modified, just free the new filter if it was created */
                free(new_filter);
            }
            new_filter = NULL;
        }
    }

    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * SR_EV_CHANGE and SR_EV_ENABLED validation (read-only checks, no state modification)
 * ---------------------------------------------------------------------------
 */

static int
sub_change_validate_encoding(sr_session_ctx_t *session, sr_event_t event, const struct lyd_node *node)
{
    const char *value;

    value = ((struct lyd_node_term *)node)->value.ident->name;
    if (!strcmp(value, "encode-xml") || !strcmp(value, "encode-json")) {
        return SR_ERR_OK;
    } else if (!strcmp(value, "encode-cbor")) {
        SRNTF_VALIDATE_ERR(session, event, SR_ERR_UNSUPPORTED, "CBOR encoding is not yet supported.");
        return SR_ERR_UNSUPPORTED;
    } else {
        SRNTF_VALIDATE_ERR(session, event, SR_ERR_UNSUPPORTED, "Unsupported encoding \"%s\".", value);
        return SR_ERR_UNSUPPORTED;
    }
}

static int
sub_change_validate_stream(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session, sr_event_t event,
        const char *stream, const char *xpath_filter)
{
    int rc = SR_ERR_OK;
    const struct ly_ctx *ly_ctx;
    struct ly_set *mod_set = NULL;

    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);
    if ((rc = srsn_stream_collect_mods(stream, xpath_filter, ly_ctx, &mod_set))) {
        if (rc == SR_ERR_NOT_FOUND) {
            SRNTF_VALIDATE_ERR(session, event, rc, "Stream \"%s\" does not match any implemented YANG module.", stream);
        }
        goto cleanup;
    }

cleanup:
    sr_session_release_context(notifd_ctx->sr_sess);
    ly_set_free(mod_set, NULL);
    return rc;
}

static int
sub_change_validate_temporal(sr_session_ctx_t *session, sr_event_t event, const struct timespec *stop_time,
        const struct timespec *start_time)
{
    int rc = SR_ERR_OK;
    struct timespec cur_ts;

    clock_gettime(CLOCK_REALTIME, &cur_ts);

    if (start_time && (timespec_cmp(&cur_ts, start_time) < 0)) {
        SRNTF_VALIDATE_ERR(session, event, SR_ERR_VALIDATION_FAILED, "Specified \"start-time\" is in the future.");
        rc = SR_ERR_VALIDATION_FAILED;
    } else if (!start_time && stop_time && (timespec_cmp(&cur_ts, stop_time) > 0)) {
        SRNTF_VALIDATE_ERR(session, event, SR_ERR_VALIDATION_FAILED, "Specified \"stop-time\" is in the past.");
        rc = SR_ERR_VALIDATION_FAILED;
    } else if (start_time && stop_time && (timespec_cmp(start_time, stop_time) > 0)) {
        SRNTF_VALIDATE_ERR(session, event, SR_ERR_VALIDATION_FAILED, "Specified \"stop-time\" is earlier than \"start-time\".");
        rc = SR_ERR_VALIDATION_FAILED;
    }

    return rc;
}

static int
sub_change_validate_subtree_filter(sr_session_ctx_t *session, sr_event_t event,
        const struct lyd_node *subtree_filter)
{
    int rc = SR_ERR_OK;
    char *xpath_filter = NULL;
    struct lyd_node *filter;

    filter = lyd_child_any(subtree_filter);
    if (!filter) {
        goto cleanup;
    }

    if ((rc = srsn_filter_subtree2xpath(filter, session, &xpath_filter))) {
        SRNTF_VALIDATE_ERR(session, event, rc, "Failed to convert subtree filter to XPath.");
        goto cleanup;
    }

cleanup:
    free(xpath_filter);
    return rc;
}

int
sub_change_validate(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session, sr_event_t event)
{
    int rc = SR_ERR_OK, r, prev_dflt;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;
    struct lyd_node *n;
    const char *stream, *xpath_filter;
    struct timespec stop_time, start_time;
    notif_sub_t *sub;

    /* validate created subscriptions */
    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/subscription", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        assert(LYD_NAME(node) && !strcmp(LYD_NAME(node), "subscription"));

        if (op != SR_OP_CREATED) {
            continue;
        }

        /* transport - validate against registered transports */
        if (!lyd_find_path(node, "transport", 0, &n)) {
            const notif_transport_ops_t *ops;

            ops = notif_transport_find_by_identity(lyd_get_value(n));
            if (!ops) {
                SRNTF_VALIDATE_ERR(session, event, SR_ERR_UNSUPPORTED, "Unsupported transport \"%s\".", lyd_get_value(n));
                rc = SR_ERR_UNSUPPORTED;
                goto cleanup;
            }
            if (ops->config_validate && (r = ops->config_validate(node))) {
                rc = r;
                goto cleanup;
            }
        }

        /* encoding */
        if (!lyd_find_path(node, "encoding", 0, &n)) {
            if ((r = sub_change_validate_encoding(session, event, n))) {
                rc = r;
                goto cleanup;
            }
        }

        /* stream must map to an existing module */
        stream = NULL;
        xpath_filter = NULL;
        if (!lyd_find_path(node, "stream", 0, &n)) {
            stream = lyd_get_value(n);
        }
        if (!lyd_find_path(node, "stream-xpath-filter", 0, &n)) {
            xpath_filter = lyd_get_value(n);
        }
        if (stream) {
            if ((r = sub_change_validate_stream(notifd_ctx, session, event, stream, xpath_filter))) {
                rc = r;
                goto cleanup;
            }
        }

        /* subtree filter must be convertible to XPath */
        if (!lyd_find_path(node, "stream-subtree-filter", 0, &n)) {
            if ((r = sub_change_validate_subtree_filter(session, event, n))) {
                rc = r;
                goto cleanup;
            }
        }

        /* temporal constraints */
        stop_time.tv_sec = 0;
        stop_time.tv_nsec = 0;
        start_time.tv_sec = 0;
        start_time.tv_nsec = 0;

        if (!lyd_find_path(node, "stop-time", 0, &n)) {
            if (ly_time_str2ts(lyd_get_value(n), &stop_time)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }
        }

        if (!lyd_find_path(node, "configured-replay", 0, &n)) {
            /* replay requested, check that the stream supports it */
            if (stream) {
                if ((r = stream_supports_replay(notifd_ctx, stream, xpath_filter, &start_time))) {
                    SRNTF_VALIDATE_ERR(session, event, r, "Stream \"%s\" does not support replay.", stream);
                    rc = r;
                    goto cleanup;
                }
            }
        }

        /* validate temporal constraints with the parsed values */
        if (stop_time.tv_sec || stop_time.tv_nsec || start_time.tv_sec || start_time.tv_nsec) {
            if ((r = sub_change_validate_temporal(session, event,
                    (stop_time.tv_sec || stop_time.tv_nsec) ? &stop_time : NULL,
                    (start_time.tv_sec || start_time.tv_nsec) ? &start_time : NULL))) {
                rc = r;
                goto cleanup;
            }
        }
    }
    sr_free_change_iter(iter);
    iter = NULL;

    /* validate modified subscription fields */
    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:subscriptions/"
            "subscription[not(@yang:operation)]//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        if ((op != SR_OP_CREATED) && (op != SR_OP_MODIFIED)) {
            continue;
        }

        node_name = LYD_NAME(node);

        if (!strcmp(node_name, "stream")) {
            /* stream changed - validate new stream exists */
            if ((r = sub_change_validate_stream(notifd_ctx, session, event, lyd_get_value(node), NULL))) {
                rc = r;
                goto cleanup;
            }

            /* if configured-replay is set on the existing sub, also check replay support for new stream */
            sub = subscription_find_by_node(notifd_ctx, node);
            if (sub && sub->replay) {
                if ((r = stream_supports_replay(notifd_ctx, lyd_get_value(node), sub->xpath_filter,
                        &start_time))) {
                    SRNTF_VALIDATE_ERR(session, event, r, "Stream \"%s\" does not support replay.", lyd_get_value(node));
                    rc = r;
                    goto cleanup;
                }
            }
        } else if (!strcmp(node_name, "encoding")) {
            if ((r = sub_change_validate_encoding(session, event, node))) {
                rc = r;
                goto cleanup;
            }
        } else if (!strcmp(node_name, "stream-subtree-filter")) {
            if ((r = sub_change_validate_subtree_filter(session, event, node))) {
                rc = r;
                goto cleanup;
            }
        } else if (!strcmp(node_name, "stop-time")) {
            if (ly_time_str2ts(lyd_get_value(node), &stop_time)) {
                rc = SR_ERR_LY;
                goto cleanup;
            }

            /* check stop-time is not in the past */
            sub = subscription_find_by_node(notifd_ctx, node);
            start_time.tv_sec = 0;
            start_time.tv_nsec = 0;
            if (sub && (sub->start_time.tv_sec || sub->start_time.tv_nsec)) {
                start_time = sub->start_time;
            }

            if ((r = sub_change_validate_temporal(session, event, &stop_time,
                    (start_time.tv_sec || start_time.tv_nsec) ? &start_time : NULL))) {
                rc = r;
                goto cleanup;
            }
        } else if (!strcmp(node_name, "configured-replay")) {
            /* replay being enabled on existing sub, check stream supports it */
            sub = subscription_find_by_node(notifd_ctx, node);
            if (sub && sub->stream) {
                if ((r = stream_supports_replay(notifd_ctx, sub->stream, sub->xpath_filter,
                        &start_time))) {
                    SRNTF_VALIDATE_ERR(session, event, r, "Stream \"%s\" does not support replay.", sub->stream);
                    rc = r;
                    goto cleanup;
                }
            }
        }
    }
    sr_free_change_iter(iter);
    iter = NULL;

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

int
filter_change_validate(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session, sr_event_t event)
{
    int rc = SR_ERR_OK, r, prev_dflt;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t op;
    const struct lyd_node *node;
    const char *prev_value, *prev_list, *node_name;

    (void)notifd_ctx;

    if ((rc = sr_get_changes_iter(session, "/ietf-subscribed-notifications:filters/stream-filter//.", &iter))) {
        goto cleanup;
    }
    while (!sr_get_change_tree_next(session, iter, &op, &node, &prev_value, &prev_list, &prev_dflt)) {
        if ((op != SR_OP_CREATED) && (op != SR_OP_MODIFIED)) {
            continue;
        }

        node_name = LYD_NAME(node);

        if (!strcmp(node_name, "stream-subtree-filter")) {
            if ((r = sub_change_validate_subtree_filter(session, event, node))) {
                rc = r;
                goto cleanup;
            }
        }
    }

cleanup:
    sr_free_change_iter(iter);
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Feature check
 * ---------------------------------------------------------------------------
 */

int
module_feature_is_enabled(notifd_ctx_t *notifd_ctx, const char *module_name, const char *feature_name, int *enabled)
{
    int rc = SR_ERR_OK;
    LY_ERR lyrc;
    const struct ly_ctx *ly_ctx = NULL;
    const struct lys_module *ly_mod;

    if (!notifd_ctx || !module_name || !feature_name || !enabled) {
        return SR_ERR_INVAL_ARG;
    }

    *enabled = 0;

    ly_ctx = sr_session_acquire_context(notifd_ctx->sr_sess);
    if (!ly_ctx) {
        return SR_ERR_INTERNAL;
    }

    ly_mod = ly_ctx_get_module_implemented(ly_ctx, module_name);
    if (!ly_mod) {
        SRNTF_LOG_WRN("Implemented module \"%s\" was not found while checking feature \"%s\".", module_name,
                feature_name);
        goto cleanup;
    }

    lyrc = lys_feature_value(ly_mod, feature_name);
    if (lyrc == LY_SUCCESS) {
        *enabled = 1;
    } else if ((lyrc != LY_ENOT) && (lyrc != LY_ENOTFOUND)) {
        SRNTF_LOG_ERR("Failed to evaluate feature \"%s\" in module \"%s\".", feature_name, module_name);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    sr_session_release_context(notifd_ctx->sr_sess);
    return rc;
}

void
notifd_ctx_destroy(notifd_ctx_t *notifd_ctx)
{
    LY_ARRAY_COUNT_TYPE i;

    if (!notifd_ctx) {
        return;
    }

    /* destroy all subscriptions (includes stopping dispatch, disconnecting receivers, freeing memory) */
    for (i = LY_ARRAY_COUNT(notifd_ctx->subs); i > 0; i--) {
        subscription_destroy(notifd_ctx, notifd_ctx->subs[i - 1]);
    }
    notifd_ctx->subs = NULL;

    /* destroy all receiver instances */
    for (i = LY_ARRAY_COUNT(notifd_ctx->recv_insts); i > 0; i--) {
        receiver_instance_destroy(notifd_ctx, notifd_ctx->recv_insts[i - 1]);
    }
    notifd_ctx->recv_insts = NULL;
}
