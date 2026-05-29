/**
 * @file notifd_common.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief common declarations shared between sysrepo-notifd source files
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

#ifndef COMMON_H_
#define COMMON_H_

#include <stdint.h>

#include "notifd.h"
#include "sysrepo.h"

#include <libyang/libyang.h>

/**
 * @brief UDP transport operations (defined in notifd_udp.c).
 */
extern const notif_transport_ops_t udp_transport_ops;

/** @brief Bitmask: include the `stream` field in a state-change notification. */
#define NOTIF_FIELD_STREAM         0x01

/** @brief Bitmask: include the `xpath-filter` field in a state-change notification. */
#define NOTIF_FIELD_XPATH_FILTER   0x02

/** @brief Bitmask: include the `stop-time` field in a state-change notification. */
#define NOTIF_FIELD_STOP_TIME      0x04

/** @brief Bitmask: include the `replay-start-time` field in a state-change notification. */
#define NOTIF_FIELD_REPLAY_START   0x08

/*
 * ---------------------------------------------------------------------------
 * Functions from notifd_config.c
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Find a mandatory descendant node of a context node by YANG path.
 *
 * If the descendant does not exist, logs an error and returns ::SR_ERR_NOT_FOUND.
 *
 * @param[in] ctx_node Ancestor YANG data node to search from.
 * @param[in] path Schema path expression passed to lyd_find_path.
 * @param[out] match Found descendant node, or NULL on failure.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if the descendant does not exist.
 */
int get_descendant_mandatory(const struct lyd_node *ctx_node, const char *path, struct lyd_node **match);

/**
 * @brief Find an optional descendant node of a context node by YANG path.
 *
 * Suppresses libyang error logging during the search because the node may
 * legitimately be absent. Does not log errors on failure.
 *
 * @param[in] ctx_node Ancestor YANG data node to search from.
 * @param[in] path Schema path expression passed to lyd_find_path.
 * @param[out] match Found descendant node, or NULL if not found.
 */
void get_descendant_optional(const struct lyd_node *ctx_node, const char *path, struct lyd_node **match);

/**
 * @brief Convert a subscription state enum value to a human-readable string.
 *
 * @param[in] state Subscription state value.
 * @return Static string "valid", "invalid", "concluded", or "unknown".
 */
const char *subscription_state2str(notif_sub_state_t state);

/**
 * @brief Convert a receiver state enum value to a human-readable string.
 *
 * @param[in] state Receiver state value.
 * @return Static string "active", "suspended", "connecting", "disconnected", or "unknown".
 */
const char *receiver_state2str(notif_recv_state_t state);

/**
 * @brief Find a subscription by its numeric ID.
 *
 * @param[in] ctx Daemon context containing the subscription array.
 * @param[in] sub_id Subscription ID to search for.
 * @return Pointer to the matching subscription, or NULL if not found.
 */
notif_sub_t *subscription_find_by_id(notifd_ctx_t *ctx, uint32_t sub_id);

/**
 * @brief Find a subscription by an arbitrary YANG node within its subtree.
 *
 * Walks up the tree from @p ctx_node to find the ancestor `subscription` list
 * entry, extracts its `id` leaf, and looks up the corresponding subscription.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] ctx_node Any YANG data node within a subscription subtree.
 * @return Pointer to the matching subscription, or NULL if not found.
 */
notif_sub_t *subscription_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node);

/**
 * @brief Find a receiver by name within a subscription.
 *
 * @param[in] sub Subscription whose receivers to search.
 * @param[in] name Receiver name to search for.
 * @return Pointer to the matching receiver, or NULL if not found.
 */
notif_receiver_t *receiver_find_by_name(notif_sub_t *sub, const char *name);

/**
 * @brief Find a receiver by an arbitrary YANG node within its subtree.
 *
 * Walks up the tree from @p ctx_node to find the ancestor `receiver` list entry,
 * extracts its `name`, then finds the parent subscription and looks up the
 * receiver by name within it.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] ctx_node Any YANG data node within a receiver subtree.
 * @return Pointer to the matching receiver, or NULL if not found.
 */
notif_receiver_t *receiver_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node);

/**
 * @brief Find a receiver instance by name.
 *
 * @param[in] ctx Daemon context containing the receiver-instance array.
 * @param[in] name Receiver-instance name to search for.
 * @return Pointer to the matching receiver instance, or NULL if not found.
 */
notif_receiver_inst_t *receiver_inst_find_by_name(notifd_ctx_t *ctx, const char *name);

/**
 * @brief Find a receiver instance by an arbitrary YANG node within its subtree.
 *
 * Walks up the tree from @p ctx_node to find the ancestor `receiver-instance`
 * list entry, extracts its `name`, and looks up the corresponding instance.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] ctx_node Any YANG data node within a receiver-instance subtree.
 * @return Pointer to the matching receiver instance, or NULL if not found.
 */
notif_receiver_inst_t *receiver_inst_find_by_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *ctx_node);

/**
 * @brief Create a new subscription from a YANG `subscription` list entry.
 *
 * Allocates a ::notif_sub_t, adds it to the daemon context's subscription array,
 * parses all fields, and sets the initial state to VALID. On parse failure,
 * disconnects receivers and invalidates the subscription.
 *
 * @param[in,out] notifd_ctx Daemon context (subscription is added to its array).
 * @param[in] node The YANG `subscription` list entry node.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int subscription_create_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node);

/**
 * @brief Destroy a subscription identified by a YANG node within its subtree.
 *
 * If the subscription was valid, sends a `subscription-terminated` notification
 * to all its receivers before destruction.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in] node YANG node within the subscription subtree to be deleted.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if the subscription cannot be found.
 */
int subscription_destroy_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node);

/**
 * @brief Create a new receiver within a subscription from a YANG `receiver` node.
 *
 * Allocates the receiver, adds it to the subscription's receiver array, parses
 * it, starts notification dispatch, attempts to connect, and if successful and
 * the subscription is valid, sends a `subscription-started` notification.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in,out] sub Parent subscription (receiver is added to its array).
 * @param[in] node The YANG `receiver` list entry node.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int receiver_create_from_node(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node);

/**
 * @brief Destroy a receiver identified by a YANG node within its subtree.
 *
 * If the receiver was active, sends a `subscription-terminated` notification
 * to it before destruction.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in,out] sub Parent subscription.
 * @param[in] node YANG node within the receiver subtree to be deleted.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if the receiver cannot be found.
 */
int receiver_destroy_from_node(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node);

/**
 * @brief Create a new receiver instance from a YANG `receiver-instance` node.
 *
 * Allocates the struct, adds it to the daemon context's array, and parses it
 * including transport-specific configuration.
 *
 * @param[in,out] notifd_ctx Daemon context (instance is added to its array).
 * @param[in] node The YANG `receiver-instance` list entry node.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int receiver_instance_create_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node);

/**
 * @brief Destroy a receiver instance identified by a YANG node within its subtree.
 *
 * Frees the instance name, calls the transport's config_destroy, and removes
 * it from the daemon context's array. Assumes no subscriptions still reference
 * this instance.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in] node YANG node within the receiver-instance subtree to be deleted.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if the instance cannot be found.
 */
int receiver_instance_destroy_from_node(notifd_ctx_t *notifd_ctx, const struct lyd_node *node);

/**
 * @brief Handle a change to the `stream` leaf of a subscription.
 *
 * On modification, updates the subscription's stream name and marks the
 * subscription as modified and needing resubscription.
 *
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `stream` leaf node with the new value.
 * @param[in] op Sysrepo change operation (only ::SR_OP_MODIFIED is handled).
 * @return ::SR_ERR_OK on success, ::SR_ERR_NO_MEMORY on allocation failure.
 */
int handle_stream(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `stream-filter-name` leaf of a subscription.
 *
 * On create/modify, resolves the filter name to an XPath filter string via
 * the datastore. On delete, clears the filter reference and XPath filter.
 * Marks the subscription as modified and needing resubscription.
 *
 * @param[in,out] notifd_ctx Daemon context (used to access the sysrepo session).
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `stream-filter-name` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int handle_stream_filter_name(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `stream-subtree-filter` anydata node of a subscription.
 *
 * On create/modify, extracts the filter subtree and converts it to an XPath
 * filter. On delete, clears the XPath filter. Marks the subscription as
 * modified and needing resubscription.
 *
 * @param[in,out] notifd_ctx Daemon context (used for sysrepo session).
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `stream-subtree-filter` anydata node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int handle_stream_subtree_filter(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `stream-xpath-filter` leaf of a subscription.
 *
 * On create/modify, duplicates the new XPath value. On delete, clears the
 * XPath filter. Marks the subscription as modified and needing resubscription.
 *
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `stream-xpath-filter` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NO_MEMORY on allocation failure.
 */
int handle_stream_xpath_filter(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `encoding` leaf of a subscription.
 *
 * On create/modify, parses the identity-ref into the internal encoding enum.
 * On delete, resets to ::NOTIF_ENCODING_UNSET. Marks the subscription as
 * modified but NOT needing resubscription (encoding only affects serialization).
 *
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `encoding` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_UNSUPPORTED if the encoding is not supported.
 */
int handle_encoding(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `stop-time` leaf of a subscription.
 *
 * On create/modify, parses the date-time string into a timespec. On delete,
 * zeroes out the stop time. Marks the subscription as modified and needing
 * resubscription.
 *
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `stop-time` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_LY if the date-time string cannot be parsed.
 */
int handle_stop_time(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `configured-replay` leaf of a subscription.
 *
 * On create, enables replay and validates that the stream supports it, then
 * sets the subscription start time to the earliest replay start time. On delete,
 * disables replay and clears the start time.
 *
 * @param[in,out] notifd_ctx Daemon context (used to check replay support).
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `configured-replay` leaf node (type empty).
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_UNSUPPORTED if the stream does not support replay.
 */
int handle_configured_replay(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `purpose` leaf of a subscription.
 *
 * On create/modify, duplicates the new purpose string. On delete, frees it.
 * Marks the subscription as modified but NOT needing resubscription (purpose
 * is metadata only).
 *
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `purpose` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NO_MEMORY on allocation failure.
 */
int handle_purpose(notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `source-address` leaf of a subscription.
 *
 * On create/modify/delete, updates the local address and reconnects ALL
 * receivers in the subscription (a new source address requires new sockets).
 * Implements rollback: if reconnecting receiver @c i fails, disconnects all
 * previously reconnected receivers [0..i-1].
 *
 * @param[in,out] notifd_ctx Daemon context (used for receiver reconnection).
 * @param[in,out] sub Subscription being modified.
 * @param[in] node The YANG `source-address` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int handle_source_address(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Dispatch a configuration change for a receiver instance to its transport.
 *
 * If the receiver instance already has its ops set, delegates directly to the
 * transport's config_change callback. Otherwise, tries to identify the transport
 * by matching the changed node's name against registered transport container
 * names, which also sets the instance's ops and type.
 *
 * @param[in,out] recv_inst Receiver instance being modified.
 * @param[in] node Changed YANG data node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, error code from the transport's config_change on failure.
 */
int receiver_inst_config_change(notif_receiver_inst_t *recv_inst, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to the `receiver-instance-ref` leaf within a subscription receiver.
 *
 * On create/modify, looks up the named receiver instance and reconnects the
 * receiver to it. On delete, disconnects the receiver.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in,out] sub Parent subscription.
 * @param[in] node The YANG `receiver-instance-ref` leaf node.
 * @param[in] op Sysrepo change operation.
 * @return ::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if the receiver or instance cannot be found,
 *         or error codes from notif_receiver_reconnect.
 */
int handle_receiver_instance_ref(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Handle a change to a `stream-filter` entry in the global filters list.
 *
 * When a named filter changes, finds all subscriptions that reference it by
 * name and updates their xpath_filter accordingly. Only marks a subscription
 * for resubscription if the effective XPath filter actually changed.
 *
 * @param[in,out] notifd_ctx Daemon context.
 * @param[in] node The changed filter node (either `stream-subtree-filter` or `stream-xpath-filter`).
 * @param[in] is_subtree Non-zero if the changed node is a subtree filter, zero if it is an xpath filter.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int handle_stream_filter(notifd_ctx_t *notifd_ctx, const struct lyd_node *node, int is_subtree);

/**
 * @brief Post-processing pass after subscription configuration changes.
 *
 * For subscriptions flagged resubscribe: calls subscription_resubscribe; on
 * success marks VALID, on failure invalidates. For subscriptions flagged
 * modified or with a modif_err_reason: if VALID, sends `subscription-modified`;
 * if INVALID, sends `subscription-terminated` with the error reason.
 * Resets the modified, resubscribe, and modif_err_reason flags.
 *
 * @param[in,out] notifd_ctx Daemon context.
 */
void process_modified_subscriptions(notifd_ctx_t *notifd_ctx);

/**
 * @brief Post-processing pass after receiver-instance configuration changes.
 *
 * Iterates all receiver instances flagged as modified and reconnects every
 * receiver across all subscriptions that references each instance. Then
 * clears the modified flag.
 *
 * @param[in,out] notifd_ctx Daemon context.
 */
void process_modified_receiver_instances(notifd_ctx_t *notifd_ctx);

/**
 * @brief Resubscribe all receivers of a subscription to apply parameter changes.
 *
 * For each receiver: stops the current notification dispatch, then starts it
 * again with the updated parameters.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in,out] sub Subscription to resubscribe.
 * @return ::SR_ERR_OK on success, error code from notification_dispatch_start on failure.
 */
int subscription_resubscribe(notifd_ctx_t *notifd_ctx, notif_sub_t *sub);

/**
 * @brief Validate subscription changes during SR_EV_CHANGE (read-only).
 *
 * Validates transport identity, encoding, stream existence, subtree filter
 * convertibility, configured-replay stream support, and temporal constraints
 * (start/stop time). Does not modify any state.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in,out] session Sysrepo change session (error messages may be set on it).
 * @return ::SR_ERR_OK if all validations pass, error code on validation failure.
 */
int sub_change_validate(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session);

/**
 * @brief Validate filter changes during SR_EV_CHANGE (read-only).
 *
 * Validates that any newly created or modified `stream-subtree-filter` entries
 * in the global filters list can be converted to XPath. Does not modify any state.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] session Sysrepo change session.
 * @return ::SR_ERR_OK if all subtree filters are valid, error code on failure.
 */
int filter_change_validate(notifd_ctx_t *notifd_ctx, sr_session_ctx_t *session);

/**
 * @brief Check whether a specific YANG feature is enabled in a given module.
 *
 * @param[in] notifd_ctx Daemon context (used to acquire the libyang context).
 * @param[in] module_name YANG module name to check.
 * @param[in] feature_name Feature name within the module.
 * @param[out] enabled Set to 1 if the feature is enabled, 0 otherwise (including if the module is not found).
 * @return ::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if any required argument is NULL,
 *         ::SR_ERR_INTERNAL if the libyang context cannot be acquired.
 */
int module_feature_is_enabled(notifd_ctx_t *notifd_ctx, const char *module_name, const char *feature_name, int *enabled);

/**
 * @brief Tear down the entire daemon context.
 *
 * Destroys all subscriptions (stopping dispatch, disconnecting receivers,
 * freeing all memory) and all receiver instances. Sets the arrays to NULL.
 * The ::notifd_ctx_t struct itself is NOT freed (caller's responsibility).
 *
 * @param[in,out] notifd_ctx Daemon context to destroy. If NULL, returns immediately.
 */
void notifd_ctx_destroy(notifd_ctx_t *notifd_ctx);

/*
 * ---------------------------------------------------------------------------
 * Functions from notifd_runtime.c
 * ---------------------------------------------------------------------------
 */

/**
 * @brief Compare two timespec values lexicographically.
 *
 * @param[in] ts1 First timestamp.
 * @param[in] ts2 Second timestamp.
 * @return -1 if @p ts1 < @p ts2, 1 if @p ts1 > @p ts2, 0 if equal.
 */
int timespec_cmp(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Send a `subscription-started` notification to one or all receivers.
 *
 * Includes stream, xpath-filter, stop-time, and replay-start-time fields.
 * Does not skip inactive receivers -- send failures are fatal.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription that has started.
 * @param[in] receiver Specific receiver, or NULL to broadcast to all receivers of @p sub.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int subscription_started_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver);

/**
 * @brief Send a `subscription-terminated` notification to one or all receivers.
 *
 * Includes only the `id` and `reason` fields. Skips inactive receivers silently.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription being terminated.
 * @param[in] receiver Specific receiver, or NULL to broadcast to all receivers of @p sub.
 * @param[in] reason YANG identity-ref reason string (e.g. "ietf-subscribed-notifications:no-such-subscription").
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int subscription_terminated_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver, const char *reason);

/**
 * @brief Send a `subscription-modified` notification to one or all receivers.
 *
 * Includes stream, xpath-filter, stop-time, and replay-start-time fields.
 * Skips inactive receivers silently.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription that was modified.
 * @param[in] receiver Specific receiver, or NULL to broadcast to all receivers of @p sub.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int subscription_modified_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver);

/**
 * @brief Send a `subscription-completed` notification to one or all receivers.
 *
 * Includes only the `id` field. Skips inactive receivers silently.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Subscription that has completed (reached stop time).
 * @param[in] receiver Specific receiver, or NULL to broadcast to all receivers of @p sub.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int subscription_completed_notif_send(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver);

/**
 * @brief Check whether a receiver currently has an active transport connection.
 *
 * NULL-safe: returns 0 for NULL receiver or NULL ops.
 *
 * @param[in] receiver Receiver to check.
 * @return 1 if connected, 0 otherwise.
 */
int notif_receiver_is_connected(notif_receiver_t *receiver);

/**
 * @brief Establish a transport connection for a receiver.
 *
 * If already connected or no instance/ops configured, succeeds silently.
 * Does NOT modify receiver->state; the caller is responsible for updating it.
 *
 * @param[in] receiver Receiver to connect.
 * @return ::SR_ERR_OK on success (or no-op), error code from the transport's connect on failure.
 */
int notif_receiver_connect(notif_receiver_t *receiver);

/**
 * @brief Tear down a receiver's transport connection.
 *
 * Calls the transport's disconnect callback which must close resources,
 * free conn_ctx, and set it to NULL. Does NOT modify receiver->state;
 * the caller is responsible for updating it.
 *
 * @param[in] receiver Receiver to disconnect.
 */
void notif_receiver_disconnect(notif_receiver_t *receiver);

/**
 * @brief Attempt to reconnect a disconnected receiver using exponential backoff.
 *
 * On successful reconnection, sends a `subscription-started` notification
 * (per RFC 8692 Section 2.1.2) and sets the receiver state to ACTIVE.
 * Delay = NOTIFD_RECV_RECONNECT_BASE_SEC << reconnect_attempts, capped
 * at NOTIFD_RECV_RECONNECT_MAX_SEC (60s).
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] receiver Disconnected receiver to reconnect.
 * @return ::SR_ERR_OK on success, ::SR_ERR_OPERATION_FAILED if backoff has not
 *         elapsed or reconnection failed, or other error codes.
 */
int notif_receiver_backoff_reconnect(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver);

/**
 * @brief Fully reconnect a receiver with the complete lifecycle.
 *
 * If currently connected, sends `subscription-terminated` before disconnecting.
 * Optionally updates the receiver's instance/ops if @p new_inst is provided.
 * Then connects and sends `subscription-started`. On any error, the receiver
 * is disconnected and set to DISCONNECTED state.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] sub Parent subscription of the receiver.
 * @param[in] receiver Receiver to reconnect.
 * @param[in] new_inst New receiver instance to assign, or NULL to keep the existing instance.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int notif_receiver_reconnect(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver, notif_receiver_inst_t *new_inst);

/**
 * @brief Send a single notification to a specific receiver over its transport.
 *
 * Enforces protocol ordering: a `subscription-started` must have been delivered
 * before any other notification type can be sent. If @p timestamp is NULL, the
 * current time is used.
 *
 * @param[in] notifd_ctx Daemon context.
 * @param[in] receiver Receiver to send to.
 * @param[in] notif Notification data tree to send.
 * @param[in] timestamp Event timestamp, or NULL for current time.
 * @param[in] encoding Encoding format for the notification payload.
 * @return ::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if receiver or notif is NULL,
 *         ::SR_ERR_OPERATION_FAILED if the receiver is not connected or not active,
 *         ::SR_ERR_UNSUPPORTED if no transport ops available, or other error codes.
 */
int notif_receiver_send(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver, const struct lyd_node *notif,
        const struct timespec *timestamp, notif_encoding_t encoding);

/**
 * @brief Start notification dispatch for a receiver via srsn.
 *
 * Subscribes to the configured notification stream and adds a file-descriptor-based
 * dispatch entry. This begins the flow of notifications from sysrepo to the receiver.
 *
 * @param[in] notifd_ctx Daemon context (its sr_sess is used as the srsn subscription session).
 * @param[in] sub Subscription defining the stream, filter, and stop/start times.
 * @param[in] receiver Receiver whose srsn_data and cb_data will be populated.
 * @return ::SR_ERR_OK on success, error code on failure.
 */
int notification_dispatch_start(notifd_ctx_t *notifd_ctx, notif_sub_t *sub, notif_receiver_t *receiver);

/**
 * @brief Stop notification dispatch for a receiver.
 *
 * Terminates the srsn subscription and cleans up resources. Temporarily drops
 * the state write lock to allow srsn_terminate() to invoke the notification
 * callback (which acquires the state read lock).
 *
 * @warning The caller MUST hold both state_rwlock (write) AND config_apply_mutex.
 * The config_apply_mutex prevents another thread from stealing the write-lock
 * in the unlock/relock window.
 *
 * @param[in] notifd_ctx Daemon context (its state_rwlock is temporarily unlocked/relocked).
 * @param[in] receiver Receiver whose dispatch is being stopped.
 */
void notification_dispatch_stop(notifd_ctx_t *notifd_ctx, notif_receiver_t *receiver);

/**
 * @brief Main notification callback invoked by the srsn dispatch thread.
 *
 * Checks subscription validity, handles stop-time expiration (converting
 * srsn's `subscription-terminated` into `subscription-completed` per RFC 8692),
 * attempts automatic reconnection of disconnected receivers with backoff,
 * and delivers the notification. May upgrade from a read lock to a write lock
 * for stop-time handling or receiver reconnection.
 *
 * @param[in] notif The incoming notification data tree.
 * @param[in] timestamp Event timestamp of the notification.
 * @param[in] cb_data User data pointer, must be a pointer to ::notif_cb_data_t.
 */
void notifd_notification_cb(const struct lyd_node *notif, const struct timespec *timestamp, void *cb_data);

/*
 * General utility functions
*/

/**
 * @brief Acquire a mutex lock with optional timeout and error reporting.
 *
 * @param[in] mutex Mutex to lock.
 * @param[in] timeout_ms Timeout in milliseconds, 0 for blocking.
 * @param[in] func Calling function name for error reporting.
 * @return SR_ERR_OK on success, SR_ERR_TIME_OUT on timeout, SR_ERR_INTERNAL on other errors.
 */
int notifd_mutex_lock(pthread_mutex_t *mutex, uint32_t timeout_ms, const char *func);

/**
 * @brief Unlock a mutex lock.
 *
 * @param[in] mutex Mutex to unlock.
 * @param[in] func Calling function name for error reporting.
 */
void notifd_mutex_unlock(pthread_mutex_t *mutex, const char *func);

/**
 * @brief Acquire a read or write lock on a rwlock with optional timeout and error reporting.
 *
 * @param[in] lock RW lock to lock.
 * @param[in] is_write Whether to acquire a write lock (1) or read lock (0).
 * @param[in] timeout_ms Timeout in milliseconds, 0 for blocking.
 * @param[in] func Calling function name for error reporting.
 * @return SR_ERR_OK on success, SR_ERR_TIME_OUT on timeout, SR_ERR_INTERNAL on other errors.
 */
int notifd_rwlock_lock(pthread_rwlock_t *lock, int is_write, uint32_t timeout_ms, const char *func);

/**
 * @brief Unlock a rwlock.
 *
 * @param[in] lock RW lock to unlock.
 * @param[in] func Calling function name for error reporting.
 */
void notifd_rwlock_unlock(pthread_rwlock_t *lock, const char *func);

#endif /* COMMON_H_ */
