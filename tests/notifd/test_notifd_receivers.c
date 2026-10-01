/**
 * @file test_notifd_receivers.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd receivers and their operational data
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

#include <arpa/inet.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/**
 * @brief Test: Retrieve all supported operational data leaves for a subscription.
 */
static void
test_oper_data_get_all_supported(void **state)
{
    struct tnotifd_state *st = *state;
    char *value = NULL;

    setup_sub(st, 90, NULL);
    skip_notif(st, SUB_STARTED);

    /* some notifications may remain in the replay log at the time we read operational data, so
     * replay-start-time is optional; when present it must have a value */
    if (!try_oper(st, &value, SUB_XP "/replay-start-time", 90)) {
        assert_non_null(value);
        free(value);
    }

    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 90);
    assert_oper(st, "active", RECV_XP "/state", 90, TEST_RECV);
    assert_oper(st, "0", RECV_XP "/excluded-event-records", 90, TEST_RECV);

    /* sent-event-records counts event records, not subscription state change notifications, so
     * trigger a real one */
    set_node(st, "90", "/test:test-leaf");
    apply_changes(st);
    skip_notif(st, NCC);

    /* the counter is updated after the send, so poll instead of reading it once */
    wait_oper_above(st, 0, RECV_XP "/sent-event-records", 90, TEST_RECV);
}

/**
 * @brief Test: sent-event-records operational value changes after another sent notification.
 */
static void
test_oper_data_sent_event_records_change(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t sent_before, sent_after;

    setup_sub(st, 91, "stream-xpath-filter", NCC, NULL);

    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &sent_before, RECV_XP "/sent-event-records", 91, TEST_RECV), 0);

    set_node(st, "67", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);

    assert_int_equal(try_oper_u64(st, &sent_after, RECV_XP "/sent-event-records", 91, TEST_RECV), 0);
    assert_true(sent_after > sent_before);
}

/**
 * @brief Test: Receiver reset action reconnects the receiver and delivery continues.
 */
static void
test_receiver_reset_action(void **state)
{
    struct tnotifd_state *st = *state;
    sr_val_t *output = NULL;
    char path[512];
    size_t output_count = 0;

    setup_sub(st, 94, "stream-xpath-filter", NCC, NULL);

    skip_notif(st, SUB_STARTED);

    assert_oper(st, "active", RECV_XP "/state", 94, TEST_RECV);

    /* perform the receiver reset action */
    snprintf(path, sizeof path, RECV_XP "/reset", 94, TEST_RECV);
    assert_int_equal(sr_rpc_send(st->sess, path, NULL, 0, 0, &output, &output_count), SR_ERR_OK);
    assert_non_null(output);
    assert_int_equal(output_count, 1);
    sr_free_values(output, output_count);

    /* the daemon reconnects and announces itself with subscription-started */
    skip_notif(st, SUB_STARTED);
    assert_oper(st, "active", RECV_XP "/state", 94, TEST_RECV);

    /* and delivery continues */
    set_node(st, "104", "/test:test-leaf");
    apply_changes(st);
    skip_notif(st, NCC);

    assert_oper(st, "active", RECV_XP "/state", 94, TEST_RECV);
}

/**
 * @brief Test: Modify subscription source-address and verify sender source IP changes.
 */
static void
test_source_address_modify(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    char first_source[INET_ADDRSTRLEN] = {0};
    char second_source[INET_ADDRSTRLEN] = {0};
    char alternate_source[INET_ADDRSTRLEN] = {0};
    const char *initial_source = "127.0.0.1";

    if (!find_alternate_loopback_ipv4(initial_source, alternate_source, sizeof alternate_source)) {
        skip();
        return;
    }

    TLOG_INF("Testing source-address change from %s to %s", initial_source, alternate_source);

    setup_sub(st, 92, "source-address", initial_source, NULL);

    notif = expect_notif_src(st, SUB_STARTED, first_source, sizeof first_source);
    assert_string_equal(first_source, initial_source);
    lyd_free_all(notif);

    set_node(st, alternate_source, SUB_XP "/source-address", 92);
    apply_changes(st);

    /* the subscription-modified must come from the new source IP */
    notif = expect_notif_src(st, SUB_MODIFIED, second_source, sizeof second_source);
    assert_string_equal(second_source, alternate_source);
    lyd_free_all(notif);
}

/**
 * @brief Test: Change receiver instance reference from one receiver to another.
 */
static void
test_receiver_instance_ref_change(void **state)
{
    struct tnotifd_state *st = *state;
    uint16_t recv2_port = 0;
    int recv2_sockfd;

    /* a socket for the second receiver, its port is assigned by the system */
    recv2_sockfd = create_udp_receiver_socket(&recv2_port);
    assert_true(recv2_sockfd >= 0);

    add_recv_inst(st, "recv-1", st->udp_port, NULL);
    add_recv_inst(st, "recv-2", recv2_port, NULL);

    add_sub(st, 230, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    bind_sub_recv(st, 230, TEST_RECV, "recv-1");
    apply_changes(st);

    drain_notifs(st);

    /* point the subscription at the second receiver instance */
    bind_sub_recv(st, 230, TEST_RECV, "recv-2");
    apply_changes(st);

    /* the old receiver is terminated and the new one started */
    skip_notif(st, SUB_TERMINATED);
    lyd_free_all(expect_notif_on(st, recv2_sockfd, SUB_STARTED));

    close(recv2_sockfd);
}

/**
 * @brief Test: adding and removing receivers of a live subscription keeps the dispatch working.
 */
static void
test_receiver_add_delete_dispatch(void **state)
{
    struct tnotifd_state *st = *state;
    char recv_name[16], *sub_state;
    int i;

    /* subscription with a single receiver "recv1", only config change notifications */
    setup_sub(st, 210, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    /* each added receiver reallocates the receivers array, moving the already dispatched ones */
    for (i = 2; i <= 4; ++i) {
        snprintf(recv_name, sizeof recv_name, "recv%d", i);
        bind_sub_recv(st, 210, recv_name, TEST_RECV_INST);
        apply_changes(st);
        drain_notifs(st);
    }

    /* deleting a receiver stops its dispatch and moves the last receiver into its place */
    for (i = 1; i <= 3; ++i) {
        snprintf(recv_name, sizeof recv_name, "recv%d", i);
        del_node(st, RECV_XP, 210, recv_name);
        apply_changes(st);
        drain_notifs(st);
    }

    /* notifd must still be alive and serving operational data */
    sub_state = get_oper(st, SUB_XP "/configured-subscription-state", 210);
    free(sub_state);

    /* and it must still process configuration changes and set up new dispatches, so replace the
     * churned subscription with a fresh one and expect it to come up normally */
    del_node(st, SUB_XP, 210);
    apply_changes(st);
    drain_notifs(st);

    setup_sub(st, 211, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
}

/**
 * @brief Test: deleting one receiver leaves the subscription and its other receivers alone.
 */
static void
test_receiver_delete_keeps_subscription(void **state)
{
    struct tnotifd_state *st = *state;

    /* subscription with receivers "recv1" and "recv2" */
    setup_sub(st, 220, "stream-xpath-filter", NCC, NULL);
    bind_sub_recv(st, 220, "recv2", TEST_RECV_INST);
    apply_changes(st);

    drain_notifs(st);

    del_node(st, RECV_XP, 220, TEST_RECV);
    apply_changes(st);

    /* only the deleted receiver may be terminated, "recv2" must be left alone */
    assert_int_equal(count_notifs(st, SUB_TERMINATED), 1);

    /* and the subscription itself must still be valid */
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 220);

    /* "recv2" must still receive notifications */
    set_node(st, "220", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_oper_data_get_all_supported, tnotifd_reset),
        cmocka_unit_test_setup(test_oper_data_sent_event_records_change, tnotifd_reset),
        cmocka_unit_test_setup(test_receiver_reset_action, tnotifd_reset),
        cmocka_unit_test_setup(test_source_address_modify, tnotifd_reset),
        cmocka_unit_test_setup(test_receiver_instance_ref_change, tnotifd_reset),
        cmocka_unit_test_setup(test_receiver_add_delete_dispatch, tnotifd_reset),
        cmocka_unit_test_setup(test_receiver_delete_keeps_subscription, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
