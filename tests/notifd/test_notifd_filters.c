/**
 * @file test_notifd_filters.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd stream filters
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

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/**
 * @brief Test: XPath filter that matches notifications.
 */
static void
test_xpath_filter_match(void **state)
{
    struct tnotifd_state *st = *state;

    setup_sub(st, 50, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "42", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: XPath filter that does not match notifications.
 */
static void
test_xpath_filter_nomatch(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t baseline;

    setup_sub(st, 51, "stream-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='startup']", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 51, TEST_RECV), 0);

    /* make a configuration change to running datastore */
    set_node(st, "55", "/test:test-leaf");
    apply_changes(st);

    /* the counter incrementing proves the daemon filtered the notification out */
    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 51, TEST_RECV);

    /* the counter proves the daemon filtered it, this proves it put nothing on the wire */
    expect_no_notif(st, NULL);
}

/**
 * @brief Test: XPath filter with edit target content filtering.
 */
static void
test_xpath_filter_edit_target(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t baseline;

    setup_sub(st, 52, "stream-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[edit/target=\"/test:test-leaf\"]", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 52, TEST_RECV), 0);

    /* change a different target, this must not match the filter */
    set_node(st, "67", "/test:cont/dflt-leaf");
    apply_changes(st);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 52, TEST_RECV);
    expect_no_notif(st, NCC);

    /* change the target the filter selects, this must match */
    set_node(st, "77", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Subtree filter that matches notifications.
 */
static void
test_subtree_filter_match(void **state)
{
    struct tnotifd_state *st = *state;

    /* an empty element selects the whole notification */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\"/>";

    stage_sub(st, 60, NULL);
    add_sub_subtree_filter(st, 60, subtree_filter);
    apply_changes(st);
    skip_notif(st, SUB_STARTED);

    set_node(st, "88", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Subtree filter selecting on a containment node.
 */
static void
test_subtree_filter_datastore(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t baseline;

    /* subtree filter that matches netconf-config-change with datastore=running */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    stage_sub(st, 62, NULL);
    add_sub_subtree_filter(st, 62, subtree_filter);
    apply_changes(st);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 62, TEST_RECV), 0);

    /* change the startup datastore, the filter selects running so this must not match */
    assert_int_equal(sr_session_switch_ds(st->sess, SR_DS_STARTUP), SR_ERR_OK);
    set_node(st, "100", "/test:test-leaf");
    apply_changes(st);
    assert_int_equal(sr_session_switch_ds(st->sess, SR_DS_RUNNING), SR_ERR_OK);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 62, TEST_RECV);
    expect_no_notif(st, NCC);

    /* change the running datastore, this must match */
    set_node(st, "111", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Subscription with XPath filter reference (stream-filter-name).
 */
static void
test_filter_ref_xpath_match(void **state)
{
    struct tnotifd_state *st = *state;

    add_xpath_filter(st, "my-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='running']");
    setup_sub(st, 70, "stream-filter-name", "my-xpath-filter", NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "200", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Subscription with subtree filter reference (stream-filter-name).
 */
static void
test_filter_ref_subtree_match(void **state)
{
    struct tnotifd_state *st = *state;

    /* netconf-config-change with datastore=running, a containment node */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    add_subtree_filter(st, "my-subtree-filter", subtree_filter);
    setup_sub(st, 71, "stream-filter-name", "my-subtree-filter", NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "201", "/test:test-leaf");
    apply_changes(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Modifying a referenced XPath filter triggers subscription-modified.
 */
static void
test_filter_ref_xpath_modify(void **state)
{
    struct tnotifd_state *st = *state;

    add_xpath_filter(st, "modifiable-filter", NCC);
    setup_sub(st, 72, "stream-filter-name", "modifiable-filter", NULL);
    skip_notif(st, SUB_STARTED);

    /* modify the referenced filter */
    add_xpath_filter(st, "modifiable-filter", "/ietf-netconf-notifications:*");
    apply_changes(st);

    skip_notif(st, SUB_MODIFIED);
}

/**
 * @brief Test: Modifying a referenced subtree filter triggers subscription-modified.
 */
static void
test_filter_ref_subtree_modify(void **state)
{
    struct tnotifd_state *st = *state;

    /* initial subtree filter */
    const char *subtree_filter1 =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\"/>";

    /* modified subtree filter - more restrictive */
    const char *subtree_filter2 =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    add_subtree_filter(st, "modifiable-subtree-filter", subtree_filter1);
    setup_sub(st, 73, "stream-filter-name", "modifiable-subtree-filter", NULL);
    skip_notif(st, SUB_STARTED);

    /* modify the referenced filter */
    add_subtree_filter(st, "modifiable-subtree-filter", subtree_filter2);
    apply_changes(st);

    skip_notif(st, SUB_MODIFIED);
}

/**
 * @brief Test: Multiple subscriptions referencing the same filter.
 */
static void
test_filter_ref_multiple_subs(void **state)
{
    struct tnotifd_state *st = *state;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);
    add_xpath_filter(st, "shared-filter", NCC);

    /* create two subscriptions referencing the same filter */
    add_sub(st, 74, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "stream-filter-name", "shared-filter", NULL);
    bind_sub_recv(st, 74, TEST_RECV, TEST_RECV_INST);
    add_sub(st, 75, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "stream-filter-name", "shared-filter", NULL);
    bind_sub_recv(st, 75, TEST_RECV, TEST_RECV_INST);
    apply_changes(st);

    drain_notifs(st);

    /* modify the shared filter */
    add_xpath_filter(st, "shared-filter", "/ietf-netconf-notifications:*");
    apply_changes(st);

    /* exactly two subscription-modified notifications must arrive, one per subscription; count
     * until the socket goes quiet so that a third one fails the test instead of going unnoticed */
    assert_int_equal(count_notifs(st, SUB_MODIFIED), 2);
}

/**
 * @brief Test: XPath filter reference that does not match notifications.
 */
static void
test_filter_ref_xpath_nomatch(void **state)
{
    struct tnotifd_state *st = *state;
    uint64_t baseline;

    add_xpath_filter(st, "nomatch-filter", "/ietf-netconf-notifications:netconf-session-start");
    setup_sub(st, 76, "stream-filter-name", "nomatch-filter", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 76, TEST_RECV), 0);

    /* this generates netconf-config-change, not netconf-session-start */
    set_node(st, "34", "/test:test-leaf");
    apply_changes(st);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 76, TEST_RECV);

    /* the counter proves the daemon filtered it, this proves it put nothing on the wire */
    expect_no_notif(st, NULL);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_xpath_filter_match, tnotifd_reset),
        cmocka_unit_test_setup(test_xpath_filter_nomatch, tnotifd_reset),
        cmocka_unit_test_setup(test_xpath_filter_edit_target, tnotifd_reset),
        cmocka_unit_test_setup(test_subtree_filter_match, tnotifd_reset),
        cmocka_unit_test_setup(test_subtree_filter_datastore, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_match, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_subtree_match, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_modify, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_subtree_modify, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_multiple_subs, tnotifd_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_nomatch, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
