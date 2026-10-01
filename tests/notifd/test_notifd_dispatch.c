/**
 * @file test_notifd_dispatch.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd notification dispatch loop
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
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/*
 * ---------------------------------------------------------------------------
 * Notification dispatch loop
 * ---------------------------------------------------------------------------
 */

/** Receiver instance name of a second, healthy receiver */
#define OTHER_RECV_INST "test-recv-2"

/** Name of the second subscription receiver */
#define OTHER_RECV "recv2"

/**
 * @brief Test: a receiver whose address cannot be resolved stays connecting until reconfigured.
 */
static void
test_resolve_failure(void **state)
{
    struct tnotifd_state *st = *state;
    const sr_error_info_t *err_info = NULL;
    sr_val_t *output = NULL;
    size_t output_count = 0;
    char xpath[1024];

    /* a receiver instance that cannot be resolved and the healthy one the test listens on; the
     * name is reserved by RFC 6761 so a resolver answers it without leaving the host */
    set_node(st, "no-such-host.invalid", UDP_INST_XP "/remote-address", TEST_RECV_INST);
    set_node(st, "1", UDP_INST_XP "/remote-port", TEST_RECV_INST);
    add_recv_inst(st, OTHER_RECV_INST, st->udp_port, NULL);

    add_sub(st, 300, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    bind_sub_recv(st, 300, TEST_RECV, TEST_RECV_INST);
    bind_sub_recv(st, 300, OTHER_RECV, OTHER_RECV_INST);
    apply_changes(st);

    /* the healthy receiver is active, the unresolvable one is not */
    skip_notif(st, SUB_STARTED);
    assert_oper(st, "active", RECV_XP "/state", 300, OTHER_RECV);
    assert_oper(st, "connecting", RECV_XP "/state", 300, TEST_RECV);

    /* event records keep flowing to the healthy receiver */
    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    skip_notif(st, NCC);

    /* the reset cannot resolve the name either, it fails and leaves the receiver as it was */
    snprintf(xpath, sizeof xpath, RECV_XP "/reset", 300, TEST_RECV);
    assert_int_not_equal(sr_rpc_send(st->sess, xpath, NULL, 0, 0, &output, &output_count), SR_ERR_OK);
    assert_int_equal(sr_session_get_error(st->sess, &err_info), SR_ERR_OK);
    assert_non_null(strstr(err_info->err[0].message, "Failed to resolve the address of receiver"));
    assert_oper(st, "connecting", RECV_XP "/state", 300, TEST_RECV);

    /* applying its configuration again is what recovers it, as the data model describes */
    set_node(st, "127.0.0.1", UDP_INST_XP "/remote-address", TEST_RECV_INST);
    apply_changes(st);
    assert_oper(st, "active", RECV_XP "/state", 300, TEST_RECV);
}

/**
 * @brief Test: a notification larger than the notification pipe buffer.
 */
static void
test_dispatch_large_notification(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    struct ly_set *set = NULL;
    char key[160];
    uint32_t i;

    /* large segments so that the whole message fits into the socket receive buffer of the test */
    add_recv_inst(st, TEST_RECV_INST, st->udp_port, "enable-segmentation", "true",
            "max-segment-size", "8192", NULL);
    add_sub(st, 305, "stream", "NETCONF", "transport", UDP_TRANSPORT, "encoding", ENC_XML, NULL);
    bind_sub_recv(st, 305, TEST_RECV, TEST_RECV_INST);
    apply_changes(st);
    skip_notif(st, SUB_STARTED);

    /* one commit touching enough nodes with long keys that its netconf-config-change is more than
     * twice the pipe buffer */
    for (i = 0; i < 300; ++i) {
        snprintf(key, sizeof key, "%0128" PRIu32, i);
        set_node(st, "1", "/test:l1[k='%s']/v", key);
    }
    apply_changes(st);

    notif = expect_notif(st, NCC);
    assert_int_equal(lyd_find_xpath(notif, "edit", &set), LY_SUCCESS);
    assert_true(set->count >= 300);
    ly_set_free(set, NULL);
    lyd_free_all(notif);

    /* clean up the data the test created */
    del_node(st, "/test:l1");
    apply_changes(st);
}

/**
 * @brief Test: sent-event-records counts what the transport accepted, not what was queued.
 */
static void
test_dispatch_sent_records_not_delivered(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t sent, excluded;

    /* one receiver that can never connect and one healthy one on the test socket */
    set_node(st, "no-such-host.invalid", UDP_INST_XP "/remote-address", OTHER_RECV_INST);
    set_node(st, "1", UDP_INST_XP "/remote-port", OTHER_RECV_INST);
    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);
    add_sub(st, 307, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    bind_sub_recv(st, 307, TEST_RECV, TEST_RECV_INST);
    bind_sub_recv(st, 307, OTHER_RECV, OTHER_RECV_INST);
    apply_changes(st);
    skip_notif(st, SUB_STARTED);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    skip_notif(st, NCC);

    /* the healthy receiver got the event record */
    wait_oper_above(st, 0, RECV_XP "/sent-event-records", 307, TEST_RECV);

    /* the unreachable one did not, even though it was written into its notification pipe */
    assert_int_equal(try_oper_u64(st, &sent, RECV_XP "/sent-event-records", 307, OTHER_RECV), 0);
    assert_int_equal(sent, 0);

    /* an event record nobody could deliver is not an excluded one, only a filter excludes records */
    assert_int_equal(try_oper_u64(st, &excluded, RECV_XP "/excluded-event-records", 307, OTHER_RECV), 0);
    assert_int_equal(excluded, 0);
}

/**
 * @brief Test: excluded-event-records must not go backwards when a subscription is resubscribed.
 */
static void
test_dispatch_excluded_records_survive_reapply(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t excluded, excluded_after;

    /* a filter that matches nothing the test produces, so every event record is excluded */
    setup_sub(st, 310, "stream-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='startup']", NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    wait_oper_above(st, 0, RECV_XP "/excluded-event-records", 310, TEST_RECV);
    assert_int_equal(try_oper_u64(st, &excluded, RECV_XP "/excluded-event-records", 310, TEST_RECV), 0);

    /* a changed filter resubscribes, which gives the receiver a srsn subscription counting from zero */
    set_node(st, "/ietf-netconf-notifications:netconf-config-change[datastore='candidate']",
            SUB_XP "/stream-xpath-filter", 310);
    apply_changes(st);

    assert_int_equal(try_oper_u64(st, &excluded_after, RECV_XP "/excluded-event-records", 310, TEST_RECV), 0);
    assert_true(excluded_after >= excluded);
}

/**
 * @brief Test: SIGTERM while the dispatch loop still has notifications to deliver.
 */
static void
test_sigterm_shutdown(void **state)
{
    struct tnotifd_state *st = *state;
    char value[16];
    uint32_t i;
    int status = 0;

    setup_sub(st, 309, NULL);
    skip_notif(st, SUB_STARTED);

    /* a burst of event records, the daemon is still delivering them when the signal arrives */
    for (i = 0; i < 20; ++i) {
        snprintf(value, sizeof value, "%" PRIu32, i);
        set_node(st, value, "/test:test-leaf");
        apply_changes(st);
    }

    kill(st->notifd_pid, SIGTERM);
    assert_int_equal(waitpid(st->notifd_pid, &status, 0), st->notifd_pid);
    st->notifd_pid = 0;

    /* a clean exit, not the second-signal bail-out and not a crash */
    assert_true(WIFEXITED(status));
    assert_int_equal(WEXITSTATUS(status), EXIT_SUCCESS);

    /* the graceful shutdown ran, every valid subscription was terminated */
    skip_notif(st, SUB_TERMINATED);

    assert_int_equal(start_notifd(&st->notifd_pid), 0);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_resolve_failure, tnotifd_reset),
        cmocka_unit_test_setup(test_dispatch_large_notification, tnotifd_reset),
        cmocka_unit_test_setup(test_dispatch_sent_records_not_delivered, tnotifd_reset),
        cmocka_unit_test_setup(test_dispatch_excluded_records_survive_reapply, tnotifd_reset),
        cmocka_unit_test_setup(test_sigterm_shutdown, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
