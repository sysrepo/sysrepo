/**
 * @file tnotifd.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief common harness of the sysrepo-notifd tests
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

#ifndef SRTEST_NOTIFD_H_
#define SRTEST_NOTIFD_H_

#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "sysrepo.h"
#include "utils/udp_notif.h"

/** Total deadline for a notification expected to arrive (ms), spent in full only on failure, so not scaled */
#define NOTIF_TIMEOUT_MS 50000

/** Time the socket must stay silent for a negative assertion or a drain (ms), scale it with ::scale_timeout() */
#define QUIET_TIMEOUT_MS 300

/**
 * @brief Test state structure.
 */
struct tnotifd_state {
    sr_conn_ctx_t *conn;            /**< sysrepo connection */
    sr_session_ctx_t *sess;         /**< running datastore session */
    sr_session_ctx_t *oper_sess;    /**< operational datastore session */
    const struct ly_ctx *ly_ctx;    /**< libyang context */
    pid_t notifd_pid;               /**< PID of sysrepo-notifd process */
    srudpn_t *udp;                  /**< UDP-Notif collector receiving the notifications */
    uint32_t timeout_mul;           /**< multiplier of the fully consumed timeouts, greater than 1 under valgrind */
    sr_subscription_ctx_t *test_subscr; /**< subscription of the running test, freed by its teardown */
};

/** Subscription xpath prefix, takes a uint32_t subscription ID */
#define SUB_XP "/ietf-subscribed-notifications:subscriptions/subscription[id='%" PRIu32 "']"

/** Subscription receiver xpath prefix, takes a uint32_t subscription ID and a receiver name */
#define RECV_XP SUB_XP "/receivers/receiver[name='%s']"

/** Subscription receiver xpath without predicates, for subscribing to all of them */
#define ANY_RECV_XP "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver"

/** Receiver instance xpath prefix, takes a receiver instance name */
#define INST_XP "/ietf-subscribed-notifications:subscriptions" \
        "/ietf-subscribed-notif-receivers:receiver-instances/receiver-instance[name='%s']"

/** UDP-Notif receiver xpath prefix, takes a receiver instance name */
#define UDP_INST_XP INST_XP "/ietf-udp-notif-transport:udp-notif-receiver"

/** Named stream filter xpath prefix, takes a filter name */
#define FILTER_XP "/ietf-subscribed-notifications:filters/stream-filter[name='%s']"

/** Named yang-push selection filter xpath prefix, takes a filter ID */
#define SELECTION_FILTER_XP "/ietf-subscribed-notifications:filters/ietf-yang-push:selection-filter[filter-id='%s']"

/** Datastore identity of the yang-push subscriptions of the tests */
#define DS_RUNNING "ietf-datastores:running"

/** Transport identity of every subscription created by the tests */
#define UDP_TRANSPORT "ietf-udp-notif-transport:udp-notif"

/** Transport identity of a notification publisher other than sysrepo-notifd */
#define OTHER_TRANSPORT "notifd-other-publisher:other-notif"

/** Encoding identities */
#define ENC_XML "ietf-subscribed-notifications:encode-xml"
#define ENC_JSON "ietf-subscribed-notifications:encode-json"

/** Paths of the notifications the tests wait for */
#define SUB_STARTED "/ietf-subscribed-notifications:subscription-started"
#define SUB_MODIFIED "/ietf-subscribed-notifications:subscription-modified"
#define SUB_TERMINATED "/ietf-subscribed-notifications:subscription-terminated"
#define NCC "/ietf-netconf-notifications:netconf-config-change"
#define REPLAY_COMPLETED "/ietf-subscribed-notifications:replay-completed"
#define SUB_COMPLETED "/ietf-subscribed-notifications:subscription-completed"
#define PUSH_UPDATE "/ietf-yang-push:push-update"
#define PUSH_CHANGE_UPDATE "/ietf-yang-push:push-change-update"

/** Name of the receiver instance created by setup_sub() */
#define TEST_RECV_INST "test-recv"

/** Name of the subscription receiver created by setup_sub() */
#define TEST_RECV "recv1"

/*
 * Subscription IDs of the tests, unique so that a leaked subscription points at its test:
 *
 *   1        started              2        terminated           3        modified
 *   11-13    multiple             40       message_id           50-52    xpath filters
 *   60,62    subtree filters      70-76    filter refs          90,91    oper data
 *   92       source_address       93       configured_replay    94       receiver_reset
 *   95       replay on create
 *   100-102  started fields       110-114  encodings            130,131  segmentation
 *   200,201  stop_time            210,211  receiver churn       220      receiver delete
 *   221      restart              230      receiver inst ref    300      resolve failure
 *   305      large notification   307      sent records         309      sigterm shutdown
 *   310      excluded records
 *   500-509  yang-push periodic    510-519  yang-push on-change
 */

/**
 * @brief Scale a timeout that is spent in full (negative assertions, drains) for valgrind.
 *
 * @param[in] st Test state.
 * @param[in] timeout_ms Base timeout in milliseconds.
 * @return Scaled timeout in milliseconds.
 */
uint32_t scale_timeout(const struct tnotifd_state *st, uint32_t timeout_ms);

/**
 * @brief Start sysrepo-notifd daemon.
 *
 * @param[out] pid PID of started daemon.
 * @return 0 on success, -1 on failure.
 */
int start_notifd(pid_t *pid);

/**
 * @brief Stop sysrepo-notifd daemon.
 *
 * @param[in] pid PID of daemon to stop.
 */
void stop_notifd(pid_t pid);

/**
 * @brief Stage a leaf at a printf-formatted xpath on an explicit session, asserting success.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] value Value to set, NULL to create the node without one.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
void set_node_on(sr_session_ctx_t *sess, const char *value, const char *xpath_fmt, ...);

/**
 * @brief Stage a leaf at a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] value Value to set, NULL to create the node without one.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
void set_node(struct tnotifd_state *st, const char *value, const char *xpath_fmt, ...);

/**
 * @brief Stage a delete of a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
void del_node(struct tnotifd_state *st, const char *xpath_fmt, ...);

/**
 * @brief Stage subscription leaves on an explicit session.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs. A NULL value creates the node
 * without one, for empty leaves such as configured-replay.
 */
void add_sub_on(sr_session_ctx_t *sess, uint32_t sub_id, ...);

/**
 * @brief Stage subscription leaves.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs.
 */
void add_sub(struct tnotifd_state *st, uint32_t sub_id, ...);

/**
 * @brief Stage a udp-notif receiver instance on an explicit session.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] name Receiver instance name.
 * @param[in] port Remote port, the address is always 127.0.0.1.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs below udp-notif-receiver.
 */
void add_recv_inst_on(sr_session_ctx_t *sess, const char *name, uint32_t port, ...);

/**
 * @brief Stage a udp-notif receiver instance.
 *
 * @param[in] st Test state.
 * @param[in] name Receiver instance name.
 * @param[in] port Remote port, the address is always 127.0.0.1.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs below udp-notif-receiver.
 */
void add_recv_inst(struct tnotifd_state *st, const char *name, uint32_t port, ...);

/**
 * @brief Stage the receiver-instance-ref binding a subscription receiver to a receiver instance.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] recv_name Subscription receiver name.
 * @param[in] inst_name Receiver instance name to point at.
 */
void bind_sub_recv(struct tnotifd_state *st, uint32_t sub_id, const char *recv_name, const char *inst_name);

/**
 * @brief Stage an anydata subtree filter on a subscription.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] xml Subtree filter in XML.
 */
void add_sub_subtree_filter(struct tnotifd_state *st, uint32_t sub_id, const char *xml);

/**
 * @brief Stage a named xpath stream filter.
 *
 * @param[in] st Test state.
 * @param[in] name Filter name.
 * @param[in] xpath XPath filter expression.
 */
void add_xpath_filter(struct tnotifd_state *st, const char *name, const char *xpath);

/**
 * @brief Stage a named subtree stream filter.
 *
 * @param[in] st Test state.
 * @param[in] name Filter name.
 * @param[in] xml Subtree filter in XML.
 */
void add_subtree_filter(struct tnotifd_state *st, const char *name, const char *xml);

/**
 * @brief Apply the staged changes, asserting success.
 *
 * @param[in] st Test state.
 */
void apply_changes(struct tnotifd_state *st);

/**
 * @brief Apply the staged changes, asserting they are rejected, and discard them.
 *
 * @param[in] st Test state.
 * @param[in] rc Expected error.
 */
void apply_rejected(struct tnotifd_state *st, int rc);

/**
 * @brief Stage the common setup: a receiver instance on the test port and a subscription on the
 * NETCONF stream over udp-notif with a single receiver bound to it. Does not apply.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves.
 */
void stage_sub(struct tnotifd_state *st, uint32_t sub_id, ...);

/**
 * @brief Stage the common setup with stage_sub() and apply it.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves.
 */
void setup_sub(struct tnotifd_state *st, uint32_t sub_id, ...);

/**
 * @brief Stage a named yang-push selection filter with an xpath filter.
 *
 * @param[in] st Test state.
 * @param[in] filter_id Filter ID.
 * @param[in] xpath XPath filter expression.
 */
void add_selection_filter(struct tnotifd_state *st, const char *filter_id, const char *xpath);

/**
 * @brief Stage the common setup of a yang-push subscription of the running datastore, like stage_sub(). Does not
 * apply.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves, the update policy.
 */
void stage_ds_sub(struct tnotifd_state *st, uint32_t sub_id, ...);

/**
 * @brief Stage the common setup of a yang-push subscription with stage_ds_sub() and apply it.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves, the update policy.
 */
void setup_ds_sub(struct tnotifd_state *st, uint32_t sub_id, ...);

/**
 * @brief Assert a descendant leaf of a notification exists and has a value.
 *
 * @param[in] notif Notification to check.
 * @param[in] name Relative path of the leaf.
 * @param[in] value Expected value.
 */
void assert_notif_leaf(const struct lyd_node *notif, const char *name, const char *value);

/**
 * @brief Assert how many nodes of a data tree match an xpath.
 *
 * @param[in] tree Data tree to search.
 * @param[in] count Expected number of matches.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
void assert_node_count(const struct lyd_node *tree, uint32_t count, const char *xpath_fmt, ...);

/**
 * @brief Assert a descendant leaf of a notification is absent.
 *
 * @param[in] notif Notification to check.
 * @param[in] name Relative path of the leaf.
 */
void assert_no_notif_leaf(const struct lyd_node *notif, const char *name);

/**
 * @brief Read a leaf from the operational datastore without asserting.
 *
 * @param[in] st Test state.
 * @param[out] value Leaf value, caller must free. Untouched if the leaf is absent.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return 0 on success, -1 if the leaf could not be read.
 */
int try_oper(struct tnotifd_state *st, char **value, const char *xpath_fmt, ...);

/**
 * @brief Read a leaf from the operational datastore, asserting it exists.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return Leaf value, caller must free.
 */
char *get_oper(struct tnotifd_state *st, const char *xpath_fmt, ...);

/**
 * @brief Read a leaf from the operational datastore and assert its value.
 *
 * @param[in] st Test state.
 * @param[in] value Expected value.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 */
void assert_oper(struct tnotifd_state *st, const char *value, const char *xpath_fmt, ...);

/**
 * @brief Read a uint64 leaf from the operational datastore without asserting.
 *
 * @param[in] st Test state.
 * @param[out] value Parsed value.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return 0 on success, -1 if the leaf could not be read.
 */
int try_oper_u64(struct tnotifd_state *st, uint64_t *value, const char *xpath_fmt, ...);

/**
 * @brief Poll a uint64 operational leaf until it exceeds a baseline, asserting that it does.
 *
 * @param[in] st Test state.
 * @param[in] baseline Value the leaf must exceed.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 */
void wait_oper_above(struct tnotifd_state *st, uint64_t baseline, const char *xpath_fmt, ...);

/**
 * @brief Read a whole operational subtree in one get, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the subtree xpath.
 * @param[in] ... Format arguments.
 * @return Retrieved data, caller must release.
 */
sr_data_t *get_oper_tree(struct tnotifd_state *st, const char *xpath_fmt, ...);

/**
 * @brief Invoke the reset action of a subscription receiver, asserting it is answered.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] recv_name Receiver name.
 */
void send_reset(struct tnotifd_state *st, uint32_t sub_id, const char *recv_name);

/**
 * @brief Wait until the daemon reports no configured subscriptions left.
 *
 * @param[in] st Test state.
 */
void wait_no_subs(struct tnotifd_state *st);

/**
 * @brief Setup function - install modules, start daemon, create socket.
 */
int tnotifd_setup(void **state);

/**
 * @brief Teardown function - stop daemon, cleanup.
 */
int tnotifd_teardown(void **state);

/**
 * @brief Delete all the configuration and test data, wait for the daemon to tear the subscriptions
 * down and move to a new socket, before each test.
 */
int tnotifd_reset(void **state);

/**
 * @brief Receive one notification.
 *
 * @param[in] st Test state.
 * @param[in] udp Collector to receive on.
 * @param[in] path Path of the notification to wait for, others are discarded, NULL for any.
 * @param[in] timeout_ms Deadline of the whole call in milliseconds, already scaled.
 * @param[out] notif Received notification (caller must free), NULL on timeout.
 * @param[out] msg Optional UDP-Notif message of the notification (caller must free).
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_TIME_OUT if the deadline expired without a matching notification,
 * @return another error code on a socket or parse error.
 */
int recv_notif(struct tnotifd_state *st, srudpn_t *udp, const char *path, uint32_t timeout_ms, struct lyd_node **notif,
        srudpn_msg_t **msg);

/**
 * @brief Assert a notification with @p path arrives; return it, caller must free.
 */
struct lyd_node *expect_notif(struct tnotifd_state *st, const char *path);

/**
 * @brief As expect_notif(), also outputting the UDP-Notif message, caller must free.
 */
struct lyd_node *expect_notif_msg(struct tnotifd_state *st, const char *path, srudpn_msg_t **msg);

/**
 * @brief As expect_notif(), on an explicit collector.
 */
struct lyd_node *expect_notif_on(struct tnotifd_state *st, srudpn_t *udp, const char *path);

/**
 * @brief Assert a notification with @p path arrives, then free it.
 */
void skip_notif(struct tnotifd_state *st, const char *path);

/**
 * @brief Assert that a notification arrives for each of the given XPaths, in any order.
 *
 * @param[in] st Test state.
 * @param[in] xpaths NULL-terminated array of XPaths, each must select a node of a different notification.
 * @param[out] notifs Optional array of the received notifications, one for each of @p xpaths, caller must free.
 */
void expect_notifs(struct tnotifd_state *st, const char **xpaths, struct lyd_node **notifs);

/**
 * @brief Assert no notification with @p path arrives while the socket stays quiet.
 *
 * @param[in] st Test state.
 * @param[in] path Path that must not arrive, NULL for no notification at all.
 */
void expect_no_notif(struct tnotifd_state *st, const char *path);

/**
 * @brief Count the notifications with @p path received until the socket goes quiet.
 *
 * @param[in] st Test state.
 * @param[in] path Path of the notification to count, others are discarded.
 * @return Number of notifications matching @p path.
 */
uint32_t count_notifs(struct tnotifd_state *st, const char *path);

/**
 * @brief Discard every notification until the socket goes quiet.
 *
 * @param[in] st Test state.
 */
void drain_notifs(struct tnotifd_state *st);

/**
 * @brief Find a bindable IPv4 loopback address other than @p current_address.
 *
 * @param[in] current_address Address to skip, may be NULL.
 * @param[out] alternate_address Found address.
 * @param[in] alternate_address_len Size of @p alternate_address, at least INET_ADDRSTRLEN.
 * @return 1 if an address was found, 0 otherwise.
 */
int find_alternate_loopback_ipv4(const char *current_address, char *alternate_address, size_t alternate_address_len);

/**
 * @brief Move the test to a newly bound collector, discarding everything sent to the old one.
 *
 * @param[in] st Test state.
 * @return 0 on success, 1 on error.
 */
int renew_socket(struct tnotifd_state *st);

#endif /* SRTEST_NOTIFD_H_ */
