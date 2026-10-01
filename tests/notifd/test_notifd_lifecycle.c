/**
 * @file test_notifd_lifecycle.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd subscription lifecycle
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

#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/**
 * @brief Teardown: drop the subscription the test process created, tnotifd_reset() does not.
 */
static int
unsubscribe_test_subscr(void **state)
{
    struct tnotifd_state *st = *state;

    sr_unsubscribe(st->test_subscr);
    st->test_subscr = NULL;
    return 0;
}

/**
 * @brief Test: Create subscription, receive subscription-started and validate its UDP-Notif header.
 */
static void
test_subscription_started(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 1, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_int_equal(header.version, UDP_NOTIF_VERSION);

    /* standard space */
    assert_int_equal(header.s_flag, 0);
    assert_true((header.media_type == UDP_NOTIF_MT_JSON) || (header.media_type == UDP_NOTIF_MT_XML));

    /* no options, the notification fits into a single segment */
    assert_int_equal(header.header_len, UDP_NOTIF_HDR_SIZE);
    assert_int_equal(header.seg_count, 1);
    assert_true(header.message_len > UDP_NOTIF_HDR_SIZE);
    assert_true(header.publisher_id > 0);
    assert_true(header.message_id > 0);

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification contains all required fields.
 */
static void
test_subscription_started_fields(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    setup_sub(st, 100,
            "stream-xpath-filter", "/ietf-netconf-notifications:*",
            "encoding", ENC_XML,
            "purpose", "test-purpose", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "id", "100");
    assert_notif_leaf(notif, "stream", "NETCONF");
    assert_notif_leaf(notif, "transport", UDP_TRANSPORT);
    assert_notif_leaf(notif, "encoding", ENC_XML);
    assert_notif_leaf(notif, "purpose", "test-purpose");
    assert_notif_leaf(notif, "stream-xpath-filter", "/ietf-netconf-notifications:*");

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification with stream-filter-name.
 */
static void
test_subscription_started_filter_ref(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    add_xpath_filter(st, "field-test-filter", "/ietf-netconf-notifications:*");
    setup_sub(st, 101, "stream-filter-name", "field-test-filter", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "stream-filter-name", "field-test-filter");

    /* the choice is by-reference, so the inline filter must not be reported */
    assert_no_notif_leaf(notif, "stream-xpath-filter");

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification with JSON encoding.
 */
static void
test_subscription_started_json(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 102,
            "stream-xpath-filter", "/ietf-netconf-notifications:*",
            "encoding", ENC_JSON,
            "purpose", "test-purpose-json", NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_JSON);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "id", "102");
    assert_notif_leaf(notif, "stream", "NETCONF");
    assert_notif_leaf(notif, "transport", UDP_TRANSPORT);
    assert_notif_leaf(notif, "encoding", ENC_JSON);
    assert_notif_leaf(notif, "purpose", "test-purpose-json");
    assert_notif_leaf(notif, "stream-xpath-filter", "/ietf-netconf-notifications:*");

    lyd_free_all(notif);
}

/**
 * @brief Test: Delete subscription and receive subscription-terminated notification.
 */
static void
test_subscription_terminated(void **state)
{
    struct tnotifd_state *st = *state;

    setup_sub(st, 2, NULL);
    skip_notif(st, SUB_STARTED);

    del_node(st, SUB_XP, 2);
    apply_changes(st);

    skip_notif(st, SUB_TERMINATED);
}

/**
 * @brief Test: Modify subscription filter and receive subscription-modified notification.
 */
static void
test_subscription_modified(void **state)
{
    struct tnotifd_state *st = *state;

    setup_sub(st, 3, "stream-xpath-filter", "/ietf-netconf-notifications:*", NULL);

    /* modify the filter */
    set_node(st, "/ietf-netconf-notifications:netconf-config-change", SUB_XP "/stream-xpath-filter", 3);
    apply_changes(st);

    skip_notif(st, SUB_MODIFIED);
}

/**
 * @brief Test: Multiple subscriptions to the same receiver.
 */
static void
test_multiple_subscriptions(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif = NULL, *node = NULL;
    uint32_t id, timeout_ms = NOTIF_TIMEOUT_MS;
    int i, started_count = 0, seen[3] = {0};

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    /* create 3 subscriptions; the filter keeps out the netconf-config-change that applying this
     * very change produces, the subscription state change notifications are sent regardless of it */
    for (i = 1; i <= 3; i++) {
        add_sub(st, 10 + i, "stream", "NETCONF", "transport", UDP_TRANSPORT,
                "stream-xpath-filter", "/ietf-subscribed-notifications:*", NULL);
        bind_sub_recv(st, 10 + i, TEST_RECV, TEST_RECV_INST);
    }
    apply_changes(st);

    /* read until the socket goes quiet, so that an unexpected extra notification fails the test
     * instead of being left behind for the next one */
    while (recv_notif(st, st->udp_sockfd, NULL, timeout_ms, &notif, NULL, NULL, 0) == NOTIF_RECV_OK) {
        /* the first notification may take a while, any further one is already waiting */
        timeout_ms = scale_timeout(st, QUIET_TIMEOUT_MS);

        assert_string_equal(notif->schema->name, "subscription-started");

        /* every subscription must report started exactly once */
        assert_int_equal(lyd_find_path(notif, "id", 0, &node), LY_SUCCESS);
        id = strtoul(lyd_get_value(node), NULL, 10);
        assert_true((id >= 11) && (id <= 13));
        assert_int_equal(seen[id - 11], 0);
        seen[id - 11] = 1;
        ++started_count;

        lyd_free_all(notif);
        notif = NULL;
    }

    assert_int_equal(started_count, 3);
}

/**
 * @brief Test: Message ID incrementing.
 */
static void
test_message_id_increment(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header1, header2;

    /* filter out netconf-config-change so that the started/terminated pair are the only two
     * notifications sent to this receiver and their message IDs must be consecutive */
    setup_sub(st, 40, "stream-xpath-filter", "/ietf-subscribed-notifications:*", NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header1);
    lyd_free_all(notif);

    /* delete the subscription to generate another notification */
    del_node(st, SUB_XP, 40);
    apply_changes(st);

    notif = expect_notif_hdr(st, SUB_TERMINATED, &header2);
    lyd_free_all(notif);

    assert_int_equal(header2.message_id, header1.message_id + 1);
}

/**
 * @brief Test: creating a subscription does not deliver the config change that created it.
 */
static void
test_no_config_change_on_start(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    struct ly_set *set = NULL;

    setup_sub(st, 53, "stream-xpath-filter", NCC, NULL);

    /* only subscription-started, nothing about the commit that created the subscription */
    skip_notif(st, SUB_STARTED);
    expect_no_notif(st, NULL);

    /* a change made after the subscription exists must be delivered */
    set_node(st, "53", "/test:test-leaf");
    apply_changes(st);

    notif = expect_notif(st, NCC);

    /* and it must be that change, not the one that created the subscription */
    assert_int_equal(lyd_find_xpath(notif, "edit/target", &set), LY_SUCCESS);
    assert_int_equal(set->count, 1);
    assert_string_equal(lyd_get_value(set->dnodes[0]), "/test:test-leaf");
    ly_set_free(set, NULL);

    lyd_free_all(notif);
}

/**
 * @brief Test: Set configured-replay before replay support, then enable replay and verify delivery.
 */
static void
test_configured_replay(void **state)
{
    struct tnotifd_state *st = *state;

    setup_sub(st, 93, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);

    /* set configured-replay before enabling replay support, this must be rejected */
    set_node(st, NULL, SUB_XP "/configured-replay", 93);
    assert_int_equal(sr_apply_changes(st->sess, 0), SR_ERR_UNSUPPORTED);

    assert_int_equal(sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 1), SR_ERR_OK);

    /* make a config change, it is stored for replay (the subscription is invalid and will not
     * receive it live) */
    set_node(st, "42", "/test:test-leaf");
    apply_changes(st);

    /* set configured-replay again, now replay is supported */
    set_node(st, NULL, SUB_XP "/configured-replay", 93);
    apply_changes(st);

    /* the daemon does not order these three relative to each other */
    expect_notifs(st, (const char *[]) {SUB_MODIFIED, NCC, REPLAY_COMPLETED, NULL});
}

/**
 * @brief Teardown: disable the replay support enabled by test_configured_replay.
 */
static int
disable_replay_support(void **state)
{
    struct tnotifd_state *st = *state;

    sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 0);
    return 0;
}

/**
 * @brief Test: Stop-time reached triggers subscription-completed and concluded state, the
 * concluded subscription can then be deleted.
 */
static void
test_stop_time_concluded(void **state)
{
    struct tnotifd_state *st = *state;
    char stop_time_str[64];
    time_t now;

    /* stop-time a few seconds from now, scaled because valgrind can delay the daemon a lot */
    now = time(NULL) + (3 * st->timeout_mul);
    strftime(stop_time_str, sizeof stop_time_str, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    setup_sub(st, 200, "stop-time", stop_time_str, NULL);

    skip_notif(st, SUB_STARTED);
    skip_notif(st, SUB_COMPLETED);

    assert_oper(st, "concluded", SUB_XP "/configured-subscription-state", 200);

    /* its srsn subscription ended on its own, deleting the configuration must still work */
    del_node(st, SUB_XP, 200);
    apply_changes(st);
    wait_no_subs(st);

    /* and the daemon keeps serving new subscriptions */
    setup_sub(st, 201, NULL);
    skip_notif(st, SUB_STARTED);
}

/**
 * @brief Test: a daemon restarted over an existing configuration dispatches every receiver once.
 */
static void
test_restart_existing_config(void **state)
{
    struct tnotifd_state *st = *state;

    setup_sub(st, 221, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    stop_notifd(st->notifd_pid);
    st->notifd_pid = 0;
    drain_notifs(st);

    assert_int_equal(start_notifd(&st->notifd_pid), 0);

    /* the subscription must be picked up from the datastore and started again */
    skip_notif(st, SUB_STARTED);

    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 221);

    drain_notifs(st);

    set_node(st, "221", "/test:test-leaf");
    apply_changes(st);

    /* the restarted receiver must be dispatched exactly once */
    assert_int_equal(count_notifs(st, NCC), 1);
}

/**
 * @brief Stage a receiver instance with a foreign transport and two subscriptions using it, one with
 * the foreign transport and one with no transport at all.
 *
 * @param[in] st Test state.
 */
static void
add_other_publisher_config(struct tnotifd_state *st)
{
    /* the receiver instance xpath is transport-agnostic, only the transport case below it differs */
    set_node(st, "https://[::1]/telemetry",
            INST_XP "/notifd-other-publisher:other-notif-receiver/endpoint", "other-inst");

    add_sub(st, 241, "stream", "NETCONF", "transport", OTHER_TRANSPORT, NULL);
    bind_sub_recv(st, 241, "other-recv", "other-inst");

    /* no "transport" leaf at all */
    add_sub(st, 242, "stream", "NETCONF", NULL);
    bind_sub_recv(st, 242, "other-recv", "other-inst");
}

/**
 * @brief Operational get callback of another notification publisher, the state of its receivers.
 */
static int
other_publisher_state_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    if (!parent || !*parent) {
        return SR_ERR_OK;
    }

    /* provide the state of the receivers of the other publisher only */
    if (lyd_find_path(*parent, "name", 0, &node) || strcmp(lyd_get_value(node), "other-recv")) {
        return SR_ERR_OK;
    }
    if (lyd_new_term(*parent, NULL, "state", "suspended", 0, NULL)) {
        return SR_ERR_LY;
    }

    return SR_ERR_OK;
}

/**
 * @brief Reset action callback of another notification publisher.
 */
static int
other_publisher_reset_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* answer for the receivers of the other publisher only */
    if (lyd_find_path(lyd_parent(input), "name", 0, &node) || strcmp(lyd_get_value(node), "other-recv")) {
        return SR_ERR_OK;
    }
    if (lyd_new_term(output, NULL, "time", "2026-01-01T00:00:00Z", LYD_NEW_VAL_OUTPUT, NULL)) {
        return SR_ERR_LY;
    }

    return SR_ERR_OK;
}

/**
 * @brief Test: Subscriptions of another notification publisher are ignored, not broken.
 */
static void
test_other_publisher(void **state)
{
    struct tnotifd_state *st = *state;
    sr_data_t *data;

    /* a subscription serviced by the daemon */
    setup_sub(st, 240, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    /* neither an unimplemented transport nor a subscription without any transport may be rejected */
    add_other_publisher_config(st);
    apply_changes(st);

    /* our own established receiver still gets the change, but this daemon must not start a
     * dispatch for the foreign subscriptions */
    skip_notif(st, NCC);
    expect_no_notif(st, SUB_STARTED);

    /* one get of the whole subtree, it must not fail on the receivers the daemon does not service */
    data = get_oper_tree(st, "/ietf-subscribed-notifications:subscriptions");

    /* the state of our own receiver is provided ... */
    assert_node_count(data->tree, 1, RECV_XP "/state", 240, TEST_RECV);
    assert_node_count(data->tree, 1, SUB_XP "/configured-subscription-state", 240);

    /* ... the state of the other publisher's subscriptions is not, we know nothing about them */
    assert_node_count(data->tree, 0, RECV_XP "/state", 241, "other-recv");
    assert_node_count(data->tree, 0, SUB_XP "/configured-subscription-state", 241);
    assert_node_count(data->tree, 0, RECV_XP "/state", 242, "other-recv");
    assert_node_count(data->tree, 0, SUB_XP "/configured-subscription-state", 242);
    sr_release_data(data);

    /* modifying a foreign subscription must leave the daemon and its own subscription alone */
    set_node(st, "telemetry", SUB_XP "/purpose", 241);
    apply_changes(st);
    drain_notifs(st);
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 240);

    /* the other publisher provides the state of its receivers on the very paths the daemon uses */
    assert_int_equal(sr_oper_get_subscribe(st->sess, "ietf-subscribed-notifications", ANY_RECV_XP "/state",
            other_publisher_state_cb, NULL, SR_SUBSCR_OPER_MERGE, &st->test_subscr), SR_ERR_OK);

    /* the state of both publishers is in the operational data */
    assert_oper(st, "suspended", RECV_XP "/state", 241, "other-recv");
    assert_oper(st, "active", RECV_XP "/state", 240, TEST_RECV);

    /* the daemon must start while another publisher provides the same operational data */
    stop_notifd(st->notifd_pid);
    st->notifd_pid = 0;
    drain_notifs(st);
    assert_int_equal(start_notifd(&st->notifd_pid), 0);

    skip_notif(st, SUB_STARTED);
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 240);

    /* deleting the foreign configuration must leave our own subscription serviced */
    del_node(st, SUB_XP, 241);
    del_node(st, SUB_XP, 242);
    del_node(st, INST_XP, "other-inst");
    apply_changes(st);
    drain_notifs(st);
    assert_oper(st, "active", RECV_XP "/state", 240, TEST_RECV);

    /* both publishers subscribe the reset, each with its own priority; sysrepo keeps only the
     * reply of the lowest priority, the daemon's 0 */
    assert_int_equal(sr_rpc_subscribe_tree(st->sess, ANY_RECV_XP "/reset", other_publisher_reset_cb,
            NULL, 1, 0, &st->test_subscr), SR_ERR_OK);

    send_reset(st, 240, TEST_RECV);

    /* this daemon handled the reset for its own receiver: it dropped the connection and
     * re-established it, which it announces with subscription-started */
    skip_notif(st, SUB_STARTED);
    assert_oper(st, "active", RECV_XP "/state", 240, TEST_RECV);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_subscription_started, tnotifd_reset),
        cmocka_unit_test_setup(test_subscription_started_fields, tnotifd_reset),
        cmocka_unit_test_setup(test_subscription_started_filter_ref, tnotifd_reset),
        cmocka_unit_test_setup(test_subscription_started_json, tnotifd_reset),
        cmocka_unit_test_setup(test_subscription_terminated, tnotifd_reset),
        cmocka_unit_test_setup(test_subscription_modified, tnotifd_reset),
        cmocka_unit_test_setup(test_multiple_subscriptions, tnotifd_reset),
        cmocka_unit_test_setup(test_message_id_increment, tnotifd_reset),
        cmocka_unit_test_setup(test_no_config_change_on_start, tnotifd_reset),
        cmocka_unit_test_setup_teardown(test_configured_replay, tnotifd_reset, disable_replay_support),
        cmocka_unit_test_setup(test_restart_existing_config, tnotifd_reset),
        cmocka_unit_test_setup_teardown(test_other_publisher, tnotifd_reset, unsubscribe_test_subscr),
        cmocka_unit_test_setup(test_stop_time_concluded, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
