/**
 * @file test_notifd_yang_push.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd configured yang-push subscriptions
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
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/** Period of the periodic subscriptions of the tests, in centiseconds */
#define TEST_PERIOD "50"

/**
 * @brief Learn whether a printed notification includes a string.
 *
 * @param[in] notif Notification to print.
 * @param[in] str String to look for.
 * @return Whether @p str is included.
 */
static int
notif_has(const struct lyd_node *notif, const char *str)
{
    char *printed = NULL;
    int found;

    assert_int_equal(lyd_print_mem(&printed, notif, LYD_XML, LYD_PRINT_SHRINK), LY_SUCCESS);
    found = strstr(printed, str) ? 1 : 0;
    free(printed);
    return found;
}

/**
 * @brief Wait for a push-update whose datastore contents include a string, skipping the older ones.
 *
 * @param[in] st Test state.
 * @param[in] str String the printed push-update must include.
 * @return The push-update, caller must free.
 */
static struct lyd_node *
expect_push_update(struct tnotifd_state *st, const char *str)
{
    struct lyd_node *notif;
    int i;

    /* a few periods at most, the older data may still be pushed in the meantime */
    for (i = 0; i < 10; ++i) {
        notif = expect_notif(st, PUSH_UPDATE);
        if (notif_has(notif, str)) {
            return notif;
        }
        lyd_free_all(notif);
    }

    TLOG_ERR("No push-update includes \"%s\"", str);
    fail();
    return NULL;
}

/**
 * @brief Test: a periodic subscription reports its datastore target and policy, pushes the data and applies a
 * modified period.
 */
static void
test_yp_periodic(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "5", "/test:test-leaf");
    apply_changes(st);

    setup_ds_sub(st, 500,
            "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:periodic/period", TEST_PERIOD,
            "ietf-yang-push:periodic/anchor-time", "2026-01-01T00:00:00Z", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_notif_leaf(notif, "id", "500");
    assert_notif_leaf(notif, "ietf-yang-push:datastore", DS_RUNNING);
    assert_notif_leaf(notif, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf");
    assert_notif_leaf(notif, "ietf-yang-push:periodic/period", TEST_PERIOD);
    assert_int_equal(lyd_find_path(notif, "ietf-yang-push:periodic/anchor-time", 0, NULL), LY_SUCCESS);
    assert_notif_leaf(notif, "transport", UDP_TRANSPORT);
    assert_no_notif_leaf(notif, "stream");
    lyd_free_all(notif);

    /* the data, with the configured subscription ID */
    notif = expect_push_update(st, "<test-leaf xmlns=\"urn:test\">5</test-leaf>");
    assert_notif_leaf(notif, "id", "500");
    lyd_free_all(notif);

    /* every period, a changed value in a later one */
    set_node(st, "6", "/test:test-leaf");
    apply_changes(st);
    lyd_free_all(expect_push_update(st, "<test-leaf xmlns=\"urn:test\">6</test-leaf>"));

    /* a modified period */
    set_node(st, "60", SUB_XP "/ietf-yang-push:periodic/period", 500);
    apply_changes(st);
    notif = expect_notif(st, SUB_MODIFIED);
    assert_notif_leaf(notif, "ietf-yang-push:periodic/period", "60");
    lyd_free_all(notif);
    skip_notif(st, PUSH_UPDATE);
}

/**
 * @brief Test: a selection filter by reference, and editing that filter.
 */
static void
test_yp_selection_filter(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "7", "/test:test-leaf");
    set_node(st, "1", "/test:cont/l2[k='a']/v");
    add_selection_filter(st, "sel", "/test:test-leaf");
    setup_ds_sub(st, 502, "ietf-yang-push:selection-filter-ref", "sel",
            "ietf-yang-push:periodic/period", TEST_PERIOD, NULL);

    /* the reference is reported, not the filter */
    notif = expect_notif(st, SUB_STARTED);
    assert_notif_leaf(notif, "ietf-yang-push:selection-filter-ref", "sel");
    assert_no_notif_leaf(notif, "ietf-yang-push:datastore-xpath-filter");
    lyd_free_all(notif);

    notif = expect_push_update(st, "<test-leaf xmlns=\"urn:test\">7</test-leaf>");
    assert_false(notif_has(notif, "<l2>"));
    lyd_free_all(notif);

    /* the edited filter applies to the subscription */
    add_selection_filter(st, "sel", "/test:cont");
    apply_changes(st);
    skip_notif(st, SUB_MODIFIED);
    notif = expect_push_update(st, "<l2><k>a</k><v>1</v></l2>");
    assert_false(notif_has(notif, "<test-leaf"));
    lyd_free_all(notif);
}

/**
 * @brief Test: a stream subscription switched to a datastore one.
 */
static void
test_yp_stream_to_datastore(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    setup_sub(st, 504, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "8", "/test:test-leaf");
    del_node(st, SUB_XP "/stream", 504);
    del_node(st, SUB_XP "/stream-xpath-filter", 504);
    set_node(st, DS_RUNNING, SUB_XP "/ietf-yang-push:datastore", 504);
    set_node(st, "/test:test-leaf", SUB_XP "/ietf-yang-push:datastore-xpath-filter", 504);
    set_node(st, TEST_PERIOD, SUB_XP "/ietf-yang-push:periodic/period", 504);
    apply_changes(st);

    notif = expect_notif(st, SUB_MODIFIED);
    assert_notif_leaf(notif, "ietf-yang-push:datastore", DS_RUNNING);
    assert_no_notif_leaf(notif, "stream");
    lyd_free_all(notif);

    notif = expect_push_update(st, "<test-leaf xmlns=\"urn:test\">8</test-leaf>");
    assert_notif_leaf(notif, "id", "504");
    lyd_free_all(notif);
}

/**
 * @brief Test: the datastore subscriptions that cannot be serviced are rejected.
 */
static void
test_yp_validation(void **state)
{
    struct tnotifd_state *st = *state;
    char stop_time_str[64];
    time_t past;

    /* no datastore for ietf-datastores:intended */
    stage_ds_sub(st, 505, "ietf-yang-push:periodic/period", TEST_PERIOD, NULL);
    set_node(st, "ietf-datastores:intended", SUB_XP "/ietf-yang-push:datastore", 505);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* no update trigger */
    stage_ds_sub(st, 505, NULL);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* a period of 0 and one that does not fit in milliseconds */
    stage_ds_sub(st, 505, "ietf-yang-push:periodic/period", "0", NULL);
    apply_rejected(st, SR_ERR_UNSUPPORTED);
    stage_ds_sub(st, 505, "ietf-yang-push:periodic/period", "500000000", NULL);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* a filter with nodes that do not exist */
    stage_ds_sub(st, 505, "ietf-yang-push:periodic/period", TEST_PERIOD,
            "ietf-yang-push:datastore-xpath-filter", "/test:no-such-leaf", NULL);
    apply_rejected(st, SR_ERR_VALIDATION_FAILED);

    /* an empty subtree filter, it selects nothing */
    stage_ds_sub(st, 505, "ietf-yang-push:periodic/period", TEST_PERIOD,
            "ietf-yang-push:datastore-subtree-filter", NULL, NULL);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* no changes of factory-default to subscribe to */
    stage_ds_sub(st, 505, "ietf-yang-push:on-change/dampening-period", "0", NULL);
    set_node(st, "ietf-factory-default:factory-default", SUB_XP "/ietf-yang-push:datastore", 505);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* a dampening period that does not fit in milliseconds */
    stage_ds_sub(st, 505, "ietf-yang-push:on-change/dampening-period", "500000000", NULL);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* the same for named selection filters */
    add_selection_filter(st, "bad", "/test:no-such-leaf");
    apply_rejected(st, SR_ERR_VALIDATION_FAILED);
    set_node(st, NULL, SELECTION_FILTER_XP "/datastore-subtree-filter", "empty");
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* the same for a modified subscription */
    setup_ds_sub(st, 505, "ietf-yang-push:periodic/period", TEST_PERIOD,
            "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf", NULL);
    skip_notif(st, SUB_STARTED);
    set_node(st, "500000000", SUB_XP "/ietf-yang-push:periodic/period", 505);
    apply_rejected(st, SR_ERR_UNSUPPORTED);
    set_node(st, "/test:no-such-leaf", SUB_XP "/ietf-yang-push:datastore-xpath-filter", 505);
    apply_rejected(st, SR_ERR_VALIDATION_FAILED);
    del_node(st, SUB_XP "/ietf-yang-push:periodic", 505);
    apply_rejected(st, SR_ERR_UNSUPPORTED);

    /* a stop-time in the past, there is no replay start time to compare it with */
    past = time(NULL) - 3600;
    strftime(stop_time_str, sizeof stop_time_str, "%Y-%m-%dT%H:%M:%SZ", gmtime(&past));
    set_node(st, stop_time_str, SUB_XP "/stop-time", 505);
    apply_rejected(st, SR_ERR_VALIDATION_FAILED);

    /* the subscription stays serviced */
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 505);
    skip_notif(st, PUSH_UPDATE);
}

/**
 * @brief Wait for notifications until every one of the strings was included in one, skipping the others.
 *
 * @param[in] st Test state.
 * @param[in] path Path of the notifications to look at.
 * @param[in] strs NULL-terminated strings, each must be included in a notification.
 */
static void
expect_notifs_having(struct tnotifd_state *st, const char *path, const char **strs)
{
    struct lyd_node *notif;
    uint32_t i, count, found = 0;
    uint8_t seen[8] = {0};

    for (count = 0; strs[count]; ++count) {}
    while (found < count) {
        notif = expect_notif(st, path);
        for (i = 0; i < count; ++i) {
            if (!seen[i] && notif_has(notif, strs[i])) {
                seen[i] = 1;
                ++found;
            }
        }
        lyd_free_all(notif);
    }
}

/**
 * @brief Test: an on-change subscription starts with a push-update and reports the changes.
 */
static void
test_yp_on_change(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);

    setup_ds_sub(st, 510, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:on-change/dampening-period", "0", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_notif_leaf(notif, "ietf-yang-push:datastore", DS_RUNNING);
    assert_notif_leaf(notif, "ietf-yang-push:on-change/dampening-period", "0");
    assert_notif_leaf(notif, "ietf-yang-push:on-change/sync-on-start", "true");
    lyd_free_all(notif);

    /* sync-on-start */
    notif = expect_notif(st, PUSH_UPDATE);
    assert_notif_leaf(notif, "id", "510");
    assert_true(notif_has(notif, "<test-leaf xmlns=\"urn:test\">1</test-leaf>"));
    lyd_free_all(notif);

    /* a change, with the configured subscription ID */
    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);
    notif = expect_notif(st, PUSH_CHANGE_UPDATE);
    assert_notif_leaf(notif, "id", "510");
    assert_true(notif_has(notif, "<operation>replace</operation><target>/test:test-leaf</target>"));
    lyd_free_all(notif);
}

/**
 * @brief Test: the excluded changes are not reported, but counted.
 */
static void
test_yp_on_change_excluded(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    setup_ds_sub(st, 511, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:on-change/sync-on-start", "false",
            "ietf-yang-push:on-change/excluded-change", "replace", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_notif_leaf(notif, "ietf-yang-push:on-change/sync-on-start", "false");
    assert_notif_leaf(notif, "ietf-yang-push:on-change/excluded-change[.='replace']", "replace");
    lyd_free_all(notif);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    notif = expect_notif(st, PUSH_CHANGE_UPDATE);
    assert_true(notif_has(notif, "<operation>create</operation>"));
    lyd_free_all(notif);

    /* the replace is excluded */
    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);
    wait_oper_above(st, 0, RECV_XP "/excluded-event-records", 511, TEST_RECV);

    del_node(st, "/test:test-leaf");
    apply_changes(st);
    notif = expect_notif(st, PUSH_CHANGE_UPDATE);
    assert_true(notif_has(notif, "<operation>delete</operation>"));
    lyd_free_all(notif);

    /* there was no push-update at all */
    expect_no_notif(st, PUSH_UPDATE);
}

/**
 * @brief Test: an unfiltered on-change subscription of running is created, resubscribed and deleted while the
 * changes of every module are reported, ietf-subscribed-notifications included.
 */
static void
test_yp_on_change_all(void **state)
{
    struct tnotifd_state *st = *state;

    /* apply() asserts success, a stalled apply returns an error */
    setup_ds_sub(st, 513, "ietf-yang-push:on-change/dampening-period", "0", NULL);
    skip_notif(st, SUB_STARTED);
    skip_notif(st, PUSH_UPDATE);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    expect_notifs_having(st, PUSH_CHANGE_UPDATE, (const char *[]) {"<target>/test:test-leaf</target>", NULL});

    /* resubscribed, the new subscription starts with a push-update */
    set_node(st, "1", SUB_XP "/ietf-yang-push:on-change/dampening-period", 513);
    apply_changes(st);
    skip_notif(st, SUB_MODIFIED);
    skip_notif(st, PUSH_UPDATE);

    /* one apply changing ietf-subscribed-notifications and a covered module */
    set_node(st, "2", "/test:test-leaf");
    set_node(st, "all", SUB_XP "/purpose", 513);
    apply_changes(st);
    expect_notifs_having(st, PUSH_CHANGE_UPDATE, (const char *[]) {"<target>/test:test-leaf</target>",
                "/purpose</target>", NULL});

    del_node(st, SUB_XP, 513);
    apply_changes(st);
    skip_notif(st, SUB_TERMINATED);
}

/**
 * @brief Test: a modified subscription is sent subscription-modified followed by a push-update on every active
 * receiver, also when switched from periodic to on-change.
 */
static void
test_yp_on_change_modify(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    srudpn_t *udp2;

    assert_int_equal(srudpn_open("127.0.0.1", 0, &udp2), SR_ERR_OK);

    set_node(st, "3", "/test:test-leaf");
    set_node(st, "4", "/test:cont/l2[k='a']/v");
    add_recv_inst(st, "test-recv2", srudpn_get_port(udp2), NULL);
    stage_ds_sub(st, 514, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:periodic/period", "1000", NULL);
    bind_sub_recv(st, 514, "recv2", "test-recv2");
    apply_changes(st);
    skip_notif(st, SUB_STARTED);
    lyd_free_all(expect_notif_on(st, udp2, SUB_STARTED));

    /* switched to on-change with another filter */
    del_node(st, SUB_XP "/ietf-yang-push:periodic", 514);
    set_node(st, "0", SUB_XP "/ietf-yang-push:on-change/dampening-period", 514);
    set_node(st, "/test:cont", SUB_XP "/ietf-yang-push:datastore-xpath-filter", 514);
    apply_changes(st);

    notif = expect_notif(st, SUB_MODIFIED);
    assert_notif_leaf(notif, "ietf-yang-push:on-change/dampening-period", "0");
    assert_notif_leaf(notif, "ietf-yang-push:datastore-xpath-filter", "/test:cont");
    lyd_free_all(notif);
    lyd_free_all(expect_push_update(st, "<l2><k>a</k><v>4</v></l2>"));

    lyd_free_all(expect_notif_on(st, udp2, SUB_MODIFIED));
    notif = expect_notif_on(st, udp2, PUSH_UPDATE);
    assert_true(notif_has(notif, "<l2><k>a</k><v>4</v></l2>"));
    lyd_free_all(notif);

    /* and the changes follow on both */
    set_node(st, "5", "/test:cont/l2[k='a']/v");
    apply_changes(st);
    lyd_free_all(expect_notif(st, PUSH_CHANGE_UPDATE));
    lyd_free_all(expect_notif_on(st, udp2, PUSH_CHANGE_UPDATE));

    srudpn_close(udp2);
}

/**
 * @brief Test: a receiver reset starts it over with subscription-started and a push-update.
 */
static void
test_yp_on_change_reset(void **state)
{
    struct tnotifd_state *st = *state;

    setup_ds_sub(st, 515, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:on-change/dampening-period", "0", NULL);
    skip_notif(st, SUB_STARTED);
    skip_notif(st, PUSH_UPDATE);

    send_reset(st, 515, TEST_RECV);
    skip_notif(st, SUB_STARTED);
    skip_notif(st, PUSH_UPDATE);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_yp_periodic, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_selection_filter, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_stream_to_datastore, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_validation, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_on_change, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_on_change_excluded, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_on_change_all, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_on_change_modify, tnotifd_reset),
        cmocka_unit_test_setup(test_yp_on_change_reset, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
