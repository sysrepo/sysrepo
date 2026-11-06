/**
 * @file test_notifd_envelope.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd YANG-Push notification envelope
 *
 * @copyright
 * Copyright (c) 2026 Deutsche Telekom AG.
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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/** The envelope switch */
#define ENVELOPE_XP "/ietf-subscribed-notifications:subscriptions/ietf-yp-notification:enable-notification-envelope"

/** The envelope capabilities */
#define CAPAB_XP "/ietf-system-capabilities:system-capabilities/ietf-notification-capabilities:subscription-capabilities" \
        "/ietf-yp-notification:notification-metadata"

/** Reason of the subscription-terminated sent on an envelope switch */
#define ENVELOPE_CHANGED "ietf-yp-notification:notification-envelope-changed"

/**
 * @brief Assert a notification arrives in the expected envelope, the YANG-Push one with the metadata.
 *
 * @param[in] st Test state.
 * @param[in] path Path of the notification, others are discarded.
 * @param[in] envelope Whether in the YANG-Push envelope, otherwise in the RFC 5277 one.
 * @param[out] media_type Optional media type of the message.
 * @param[out] seq_number Optional sequence number of the YANG-Push envelope.
 * @return Received notification, caller must free.
 */
static struct lyd_node *
expect_in_envelope(struct tnotifd_state *st, const char *path, int envelope, srudpn_media_type_t *media_type,
        uint32_t *seq_number)
{
    struct lyd_node *notif;
    const struct lyd_node *env;
    srudpn_msg_t *msg;
    srudpn_notif_t *parsed;
    char hostname[256];

    notif = expect_notif_msg(st, path, &msg);
    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &parsed), SR_ERR_OK);
    env = srudpn_notif_get_envelope(parsed);
    if (envelope) {
        assert_string_equal(LYD_NAME(env), "envelope");

        /* the real hostname of the publisher */
        assert_int_equal(gethostname(hostname, sizeof hostname), 0);
        assert_string_equal(srudpn_notif_get_hostname(parsed), hostname);

        assert_non_null(srudpn_notif_get_sequence_number(parsed));
        if (seq_number) {
            *seq_number = *srudpn_notif_get_sequence_number(parsed);
        }
    } else {
        assert_string_equal(LYD_NAME(env), "notification");
    }
    if (media_type) {
        *media_type = srudpn_msg_get_media_type(msg);
    }
    srudpn_notif_free(parsed);
    srudpn_msg_free(msg);

    return notif;
}

/**
 * @brief Test: switching the envelope terminates the subscription in the old one and starts it in the new one.
 */
static void
test_envelope_switch(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    uint32_t seq, seq2;

    setup_sub(st, 200, NULL);
    notif = expect_in_envelope(st, SUB_STARTED, 0, NULL, NULL);
    lyd_free_all(notif);

    /* enable */
    set_node(st, "true", ENVELOPE_XP);
    apply_changes(st);

    notif = expect_in_envelope(st, SUB_TERMINATED, 0, NULL, NULL);
    assert_notif_leaf(notif, "id", "200");
    assert_notif_leaf(notif, "reason", ENVELOPE_CHANGED);
    lyd_free_all(notif);
    notif = expect_in_envelope(st, SUB_STARTED, 1, NULL, NULL);
    assert_notif_leaf(notif, "id", "200");
    lyd_free_all(notif);
    drain_notifs(st);

    /* an event record of the stream */
    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, NCC, 1, NULL, &seq);
    lyd_free_all(notif);

    /* disable, a record of this change may still come before the terminated */
    set_node(st, "false", ENVELOPE_XP);
    apply_changes(st);

    notif = expect_in_envelope(st, SUB_TERMINATED, 1, NULL, &seq2);
    assert_true(seq2 > seq);
    assert_notif_leaf(notif, "id", "200");
    assert_notif_leaf(notif, "reason", ENVELOPE_CHANGED);
    lyd_free_all(notif);
    notif = expect_in_envelope(st, SUB_STARTED, 0, NULL, NULL);
    assert_notif_leaf(notif, "id", "200");
    lyd_free_all(notif);

    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, NCC, 0, NULL, NULL);
    lyd_free_all(notif);
}

/**
 * @brief Test: a subscription created together with enabling the envelope only starts, in the envelope.
 */
static void
test_envelope_same_change(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "true", ENVELOPE_XP);
    stage_sub(st, 201, NULL);
    apply_changes(st);

    notif = expect_in_envelope(st, SUB_STARTED, 1, NULL, NULL);
    assert_notif_leaf(notif, "id", "201");
    lyd_free_all(notif);
    expect_no_notif(st, SUB_TERMINATED);
}

/**
 * @brief Test: notifications are sent in the envelope in every encoding.
 */
static void
test_envelope_encodings(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    srudpn_media_type_t media_type;

    set_node(st, "true", ENVELOPE_XP);
    stage_sub(st, 202, "encoding", ENC_XML, NULL);
    apply_changes(st);
    notif = expect_in_envelope(st, SUB_STARTED, 1, &media_type, NULL);
    assert_int_equal(media_type, SRUDPN_MT_XML);
    lyd_free_all(notif);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, NCC, 1, &media_type, NULL);
    assert_int_equal(media_type, SRUDPN_MT_XML);
    lyd_free_all(notif);

    set_node(st, ENC_JSON, SUB_XP "/encoding", 202);
    apply_changes(st);
    notif = expect_in_envelope(st, SUB_MODIFIED, 1, &media_type, NULL);
    assert_int_equal(media_type, SRUDPN_MT_JSON);
    lyd_free_all(notif);

#ifdef LY_HAVE_CBOR
    set_node(st, ENC_CBOR, SUB_XP "/encoding", 202);
    apply_changes(st);
    notif = expect_in_envelope(st, SUB_MODIFIED, 1, &media_type, NULL);
    assert_int_equal(media_type, SRUDPN_MT_CBOR);
    lyd_free_all(notif);

    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, NCC, 1, &media_type, NULL);
    assert_int_equal(media_type, SRUDPN_MT_CBOR);
    lyd_free_all(notif);
#endif /* LY_HAVE_CBOR */
}

/**
 * @brief Test: the yang-push updates are sent in the envelope.
 */
static void
test_envelope_yang_push(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "1", "/test:test-leaf");
    set_node(st, "true", ENVELOPE_XP);
    apply_changes(st);

    setup_ds_sub(st, 203, "ietf-yang-push:datastore-xpath-filter", "/test:test-leaf",
            "ietf-yang-push:on-change/dampening-period", "0", NULL);
    notif = expect_in_envelope(st, SUB_STARTED, 1, NULL, NULL);
    lyd_free_all(notif);

    /* sync-on-start */
    notif = expect_in_envelope(st, PUSH_UPDATE, 1, NULL, NULL);
    assert_notif_leaf(notif, "id", "203");
    lyd_free_all(notif);

    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, PUSH_CHANGE_UPDATE, 1, NULL, NULL);
    assert_notif_leaf(notif, "id", "203");
    lyd_free_all(notif);
}

/**
 * @brief Test: the sequence number is shared by the receivers, one per message.
 */
static void
test_envelope_sequence(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    uint32_t seq, seq2;

    set_node(st, "true", ENVELOPE_XP);
    stage_sub(st, 204, NULL);
    stage_sub(st, 205, NULL);
    apply_changes(st);
    skip_notif(st, SUB_STARTED);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    /* one event record for each receiver, two consecutive messages */
    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);
    notif = expect_in_envelope(st, NCC, 1, NULL, &seq);
    lyd_free_all(notif);
    notif = expect_in_envelope(st, NCC, 1, NULL, &seq2);
    lyd_free_all(notif);
    assert_true((seq2 == seq + 1) || (seq == seq2 + 1));
}

/**
 * @brief Test: a daemon restarted with the envelope enabled starts the subscriptions in it.
 */
static void
test_envelope_restart(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;

    set_node(st, "true", ENVELOPE_XP);
    setup_sub(st, 206, NULL);
    skip_notif(st, SUB_STARTED);

    stop_notifd(st->notifd_pid);
    st->notifd_pid = 0;
    drain_notifs(st);

    assert_int_equal(start_notifd(&st->notifd_pid), 0);

    notif = expect_in_envelope(st, SUB_STARTED, 1, NULL, NULL);
    assert_notif_leaf(notif, "id", "206");
    lyd_free_all(notif);
    expect_no_notif(st, SUB_TERMINATED);
}

/**
 * @brief Test: the envelope and its metadata are reported as supported.
 */
static void
test_envelope_capabilities(void **state)
{
    struct tnotifd_state *st = *state;

    assert_oper(st, "true", CAPAB_XP "/envelope");
    assert_oper(st, "true", CAPAB_XP "/metadata/hostname-sequence-number");
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_envelope_switch, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_same_change, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_encodings, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_yang_push, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_sequence, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_restart, tnotifd_reset),
        cmocka_unit_test_setup(test_envelope_capabilities, tnotifd_reset),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
