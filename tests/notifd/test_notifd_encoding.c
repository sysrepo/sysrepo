/**
 * @file test_notifd_encoding.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests of the sysrepo-notifd notification encodings and segmentation
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
#include <stdio.h>
#include <stdlib.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/** A purpose long enough to need several small segments, any reassembly error corrupts it */
#define LONG_PURPOSE \
        "segmentation-test-purpose-0123456789-0123456789-0123456789-0123456789" \
        "-0123456789-0123456789-0123456789-0123456789-0123456789-0123456789" \
        "-0123456789-0123456789-0123456789-0123456789-0123456789-0123456789"

/** max-segment-size forcing every notification to be split; the floor is the 16 byte header */
#define SMALL_SEGMENT_SIZE "128"

/**
 * @brief Test: a changed encoding applies to the following notifications.
 */
static void
test_encoding_modify(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 120, "stream-xpath-filter", NCC, "encoding", ENC_JSON, NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "1", "/test:test-leaf");
    apply_changes(st);

    notif = expect_notif_hdr(st, NCC, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_JSON);
    lyd_free_all(notif);

    /* change the encoding to XML */
    set_node(st, ENC_XML, SUB_XP "/encoding", 120);
    apply_changes(st);

    skip_notif(st, SUB_MODIFIED);

    set_node(st, "2", "/test:test-leaf");
    apply_changes(st);

    notif = expect_notif_hdr(st, NCC, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_XML);
    lyd_free_all(notif);
}

/**
 * @brief Test: Configuring CBOR encoding must be rejected (not implemented).
 */
static void
test_encoding_cbor_unsupported(void **state)
{
    struct tnotifd_state *st = *state;
    sr_session_ctx_t *tmp_sess = NULL;

    /* a throwaway session, the edit of the failing apply is dropped with it */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &tmp_sess), SR_ERR_OK);

    add_recv_inst_on(tmp_sess, TEST_RECV_INST, st->udp_port, NULL);
    add_sub_on(tmp_sess, 112, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "encoding", "ietf-udp-notif-transport:encode-cbor", NULL);
    set_node_on(tmp_sess, TEST_RECV_INST,
            RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref", 112, TEST_RECV);

    /* CBOR is not implemented by the daemon, the apply must be rejected by its validation */
    assert_int_equal(sr_apply_changes(tmp_sess, 0), SR_ERR_UNSUPPORTED);

    sr_session_stop(tmp_sess);
}

/**
 * @brief Test: without an encoding leaf, the highest-priority encoding with an enabled feature (XML) is used.
 */
static void
test_default_encoding(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 110, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);

    /* the highest-priority encoding with an enabled feature */
    assert_int_equal(header.media_type, UDP_NOTIF_MT_XML);
    assert_notif_leaf(notif, "encoding", ENC_XML);

    lyd_free_all(notif);
}

/**
 * @brief Test: a notification larger than max-segment-size is segmented and reassembles correctly.
 */
static void
test_segmentation_reassembly(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port,
            "enable-segmentation", "true", "max-segment-size", SMALL_SEGMENT_SIZE, NULL);
    add_sub(st, 130, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "encoding", ENC_XML, "purpose", LONG_PURPOSE, NULL);
    bind_sub_recv(st, 130, TEST_RECV, TEST_RECV_INST);
    apply_changes(st);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);

    /* the segmentation option must be present and the message must have needed several segments */
    assert_int_equal(header.has_segmentation, 1);
    assert_int_equal(header.header_len, UDP_NOTIF_HDR_SIZE + UDP_NOTIF_SEG_OPT_SIZE);
    assert_true(header.seg_count > 1);

    /* the reassembled payload must be exactly what was sent */
    assert_notif_leaf(notif, "id", "130");
    assert_notif_leaf(notif, "purpose", LONG_PURPOSE);

    lyd_free_all(notif);
}

/**
 * @brief Test: a notification larger than max-segment-size is dropped when segmentation is off.
 */
static void
test_segmentation_disabled(void **state)
{
    struct tnotifd_state *st = *state;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port,
            "enable-segmentation", "false", "max-segment-size", SMALL_SEGMENT_SIZE, NULL);
    add_sub(st, 131, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "encoding", ENC_XML, "purpose", LONG_PURPOSE, NULL);
    bind_sub_recv(st, 131, TEST_RECV, TEST_RECV_INST);
    apply_changes(st);

    /* the subscription-started does not fit into one segment, so nothing can be delivered */
    expect_no_notif(st, NULL);
}

/**
 * @brief Teardown: re-enable the encoding features after test_encoding_feature_disabled.
 */
static int
re_enable_encoding_features(void **state)
{
    struct tnotifd_state *st = *state;
    int ret;

    /* release context so the feature changes can acquire a write lock */
    if (st->ly_ctx) {
        sr_release_context(st->conn);
        st->ly_ctx = NULL;
    }

    /* best-effort; if it fails the next test run's setup will reinstall */
    ret = sr_enable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-xml");
    if (ret) {
        TLOG_WRN("Failed to re-enable encode-xml: %s", sr_strerror(ret));
    }
    ret = sr_enable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-json");
    if (ret) {
        TLOG_WRN("Failed to re-enable encode-json: %s", sr_strerror(ret));
    }

    /* re-acquire context for the global teardown */
    st->ly_ctx = sr_acquire_context(st->conn);

    return 0;
}

/**
 * @brief Test: Default encoding resolution skips disabled features.
 *
 * Must be the last test in the suite because it disables YANG features.
 */
static void
test_encoding_feature_disabled(void **state)
{
    struct tnotifd_state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;
    sr_session_ctx_t *tmp_sess = NULL;
    char xpath[512];
    int ret;

    /* release the context reference, the feature changes need the context write lock */
    sr_release_context(st->conn);
    st->ly_ctx = NULL;

    assert_int_equal(sr_disable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-json"), SR_ERR_OK);
    assert_int_equal(sr_disable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-xml"), SR_ERR_OK);

    /* re-acquire the context, now with both encoding features disabled */
    st->ly_ctx = sr_acquire_context(st->conn);

    /* a throwaway session, the edit of the failing apply is dropped with it */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &tmp_sess), SR_ERR_OK);

    add_recv_inst_on(tmp_sess, TEST_RECV_INST, st->udp_port, NULL);
    add_sub_on(tmp_sess, 114, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    set_node_on(tmp_sess, TEST_RECV_INST,
            RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref", 114, TEST_RECV);

    /* must fail, there is no encoding the daemon could use */
    assert_int_not_equal(sr_apply_changes(tmp_sess, 0), SR_ERR_OK);
    sr_session_stop(tmp_sess);

    sr_release_context(st->conn);
    st->ly_ctx = NULL;

    assert_int_equal(sr_enable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-json"), SR_ERR_OK);

    /* re-acquire the context, now with encode-json enabled and encode-xml disabled */
    st->ly_ctx = sr_acquire_context(st->conn);

    /* explicitly configuring a disabled-feature encoding must be rejected */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &tmp_sess), SR_ERR_OK);

    add_recv_inst_on(tmp_sess, TEST_RECV_INST, st->udp_port, NULL);
    add_sub_on(tmp_sess, 113, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    set_node_on(tmp_sess, TEST_RECV_INST,
            RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref", 113, TEST_RECV);

    /* refused when staging with a parsed context, otherwise (printed context) only by the daemon */
    snprintf(xpath, sizeof xpath, SUB_XP "/encoding", 113);
    ret = sr_set_item_str(tmp_sess, xpath, ENC_XML, NULL, 0);
    if (!ret) {
        ret = sr_apply_changes(tmp_sess, 0);
    }
    assert_int_not_equal(ret, SR_ERR_OK);
    sr_session_stop(tmp_sess);

    /* a subscription without an explicit encoding must fall back to JSON, skipping the
     * higher-priority encode-xml whose feature is disabled */
    setup_sub(st, 111, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_JSON);
    assert_notif_leaf(notif, "id", "111");
    assert_notif_leaf(notif, "encoding", ENC_JSON);
    lyd_free_all(notif);

    /* release context before the cleanup so notifd can process the deletion */
    sr_release_context(st->conn);
    st->ly_ctx = NULL;

    del_node(st, SUB_XP, 111);
    apply_changes(st);

    /* re-acquire context for the teardown function */
    st->ly_ctx = sr_acquire_context(st->conn);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_encoding_cbor_unsupported, tnotifd_reset),
        cmocka_unit_test_setup(test_default_encoding, tnotifd_reset),
        cmocka_unit_test_setup(test_encoding_modify, tnotifd_reset),
        cmocka_unit_test_setup(test_segmentation_reassembly, tnotifd_reset),
        cmocka_unit_test_setup(test_segmentation_disabled, tnotifd_reset),
        /* test_encoding_feature_disabled must be last: it disables the encoding features */
        cmocka_unit_test_setup_teardown(test_encoding_feature_disabled, tnotifd_reset, re_enable_encoding_features),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, tnotifd_setup, tnotifd_teardown);
}
