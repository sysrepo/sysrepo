/**
 * @file test_udp_notif.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief test for the UDP-Notif collector and encoder
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

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "utils/udp_notif.h"

/** Timeout of reading a message that was sent */
#define RECV_TIMEOUT_MS 2000

/** Timeout of reading when no message is expected */
#define QUIET_TIMEOUT_MS 100

/** Notification payload in the RFC 5277 XML envelope */
#define XML_PAYLOAD "<notification xmlns=\"urn:ietf:params:xml:ns:netconf:notification:1.0\">" \
        "<eventTime>2026-10-15T10:00:00Z</eventTime><notif xmlns=\"urn:t\"><leaf>value</leaf></notif></notification>"

struct state {
    struct ly_ctx *ly_ctx;
    srudpn_t *udp;
    int fd;
    struct sockaddr_in addr;
};

static int
setup(void **state)
{
    struct state *st;
    const char *mod = "module t {namespace urn:t; prefix t; notification notif {leaf leaf {type string;} "
            "leaf num {type uint8;}}}";

    st = calloc(1, sizeof *st);
    *state = st;

    if (ly_ctx_new(ly_yang_module_dir(), LY_CTX_NO_YANGLIBRARY, &st->ly_ctx) || lys_parse_mem(st->ly_ctx, mod, LYS_IN_YANG, NULL)) {
        return 1;
    }

    st->fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (st->fd == -1) {
        return 1;
    }

    return 0;
}

static int
teardown(void **state)
{
    struct state *st = *state;

    close(st->fd);
    ly_ctx_destroy(st->ly_ctx);
    free(st);
    return 0;
}

static int
setup_f(void **state)
{
    struct state *st = *state;

    /* a new collector for every test, so that the stats start at 0 */
    if (srudpn_open("127.0.0.1", 0, &st->udp)) {
        return 1;
    }

    memset(&st->addr, 0, sizeof st->addr);
    st->addr.sin_family = AF_INET;
    st->addr.sin_port = htons(srudpn_get_port(st->udp));
    st->addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return 0;
}

static int
teardown_f(void **state)
{
    struct state *st = *state;

    srudpn_close(st->udp);
    st->udp = NULL;
    return 0;
}

/**
 * @brief Build a datagram by hand, as laid out in draft-ietf-netconf-udp-notif.
 *
 * @param[out] buf Buffer for the datagram.
 * @param[in] first First header octet (Ver, S-flag, MT).
 * @param[in] header_len Header Len, including the options.
 * @param[in] opts Options following the fixed header, @p header_len - 12 octets.
 * @param[in] message_id Message ID, the publisher ID is always 7.
 * @param[in] data Data following the header.
 * @param[in] data_len Length of @p data.
 * @return Length of the datagram.
 */
static uint32_t
dgram_build(uint8_t *buf, uint8_t first, uint8_t header_len, const uint8_t *opts, uint32_t message_id,
        const char *data, uint32_t data_len)
{
    uint32_t len = header_len + data_len;

    buf[0] = first;
    buf[1] = header_len;
    buf[2] = len >> 8;
    buf[3] = len & 0xFF;
    buf[4] = 0;
    buf[5] = 0;
    buf[6] = 0;
    buf[7] = 7;
    buf[8] = message_id >> 24;
    buf[9] = (message_id >> 16) & 0xFF;
    buf[10] = (message_id >> 8) & 0xFF;
    buf[11] = message_id & 0xFF;
    if (opts) {
        memcpy(buf + 12, opts, header_len - 12);
    }
    memcpy(buf + header_len, data, data_len);

    return len;
}

/**
 * @brief Send a datagram to the collector.
 */
static void
dgram_send(struct state *st, const uint8_t *buf, uint32_t len)
{
    assert_int_equal(sendto(st->fd, buf, len, 0, (struct sockaddr *)&st->addr, sizeof st->addr), len);
}

/**
 * @brief Send a segment of a message in the XML media type from a socket.
 */
static void
seg_send_from(struct state *st, int fd, uint32_t message_id, uint16_t num, int last, const char *data,
        uint32_t data_len)
{
    uint8_t buf[256], opt[4];
    uint16_t seg_field = (num << 1) | (last ? 1 : 0);
    uint32_t len;

    opt[0] = 1;
    opt[1] = 4;
    opt[2] = seg_field >> 8;
    opt[3] = seg_field & 0xFF;
    len = dgram_build(buf, 0x22, 16, opt, message_id, data, data_len);
    assert_int_equal(sendto(fd, buf, len, 0, (struct sockaddr *)&st->addr, sizeof st->addr), len);
}

/**
 * @brief Send a segment of a message in the XML media type.
 */
static void
seg_send(struct state *st, uint32_t message_id, uint16_t num, int last, const char *data, uint32_t data_len)
{
    seg_send_from(st, st->fd, message_id, num, last, data, data_len);
}

/**
 * @brief Assert the payload of a message is ::XML_PAYLOAD.
 */
static void
assert_payload(const srudpn_msg_t *msg)
{
    const uint8_t *payload;
    uint32_t len;

    srudpn_msg_get_payload(msg, &payload, &len);
    assert_int_equal(len, strlen(XML_PAYLOAD));
    assert_memory_equal(payload, XML_PAYLOAD, len);
}

/**
 * @brief Assert the notification of a message is the one in ::XML_PAYLOAD.
 */
static void
assert_notif(struct state *st, const srudpn_msg_t *msg)
{
    srudpn_notif_t *notif;
    const struct lyd_node *node;
    struct timespec expected = {0};

    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &notif), SR_ERR_OK);
    assert_string_equal(LYD_NAME(srudpn_notif_get_envelope(notif)), "notification");
    node = srudpn_notif_get_tree(notif);
    assert_string_equal(LYD_NAME(node), "notif");
    assert_string_equal(lyd_get_value(lyd_child(node)), "value");

    assert_int_equal(ly_time_str2ts("2026-10-15T10:00:00Z", &expected), LY_SUCCESS);
    assert_int_equal(srudpn_notif_get_event_time(notif)->tv_sec, expected.tv_sec);

    srudpn_notif_free(notif);
}

/**
 * @brief Test: an unsegmented message is received with its header, payload and source and parsed.
 */
static void
test_unsegmented(void **state)
{
    struct state *st = *state;
    uint8_t buf[512];
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    char addr[SRUDPN_ADDR_STRLEN];
    uint16_t port;
    struct sockaddr_in sa;
    socklen_t sa_len = sizeof sa;

    dgram_send(st, buf, dgram_build(buf, 0x22, 12, NULL, 1000, XML_PAYLOAD, strlen(XML_PAYLOAD)));

    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->version, 1);
    assert_int_equal(srudpn_msg_get_hdr(msg)->s_flag, 0);
    assert_int_equal(srudpn_msg_get_hdr(msg)->media_type, SRUDPN_MT_XML);
    assert_int_equal(srudpn_msg_get_media_type(msg), SRUDPN_MT_XML);
    assert_int_equal(srudpn_msg_get_hdr(msg)->header_len, 12);
    assert_int_equal(srudpn_msg_get_hdr(msg)->message_len, 12 + strlen(XML_PAYLOAD));
    assert_int_equal(srudpn_msg_get_hdr(msg)->publisher_id, 7);
    assert_int_equal(srudpn_msg_get_hdr(msg)->message_id, 1000);
    assert_int_equal(srudpn_msg_get_hdr(msg)->segmented, 0);
    assert_payload(msg);
    srudpn_msg_get_source(msg, addr, &port);
    assert_string_equal(addr, "127.0.0.1");
    assert_int_equal(getsockname(st->fd, (struct sockaddr *)&sa, &sa_len), 0);
    assert_int_equal(port, ntohs(sa.sin_port));
    assert_notif(st, msg);
    srudpn_msg_free(msg);

    /* nothing else */
    assert_int_equal(srudpn_read_msg(st->udp, 0, &msg), SR_ERR_TIME_OUT);
    assert_null(msg);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.datagrams, 1);
    assert_int_equal(stats.messages, 1);
}

/**
 * @brief Test: a zero timeout reads a message already queued on the socket.
 */
static void
test_no_wait(void **state)
{
    struct state *st = *state;
    uint8_t buf[512];
    srudpn_msg_t *msg;
    struct pollfd pfd = {.events = POLLIN};

    dgram_send(st, buf, dgram_build(buf, 0x22, 12, NULL, 1000, XML_PAYLOAD, strlen(XML_PAYLOAD)));

    pfd.fd = srudpn_get_fd(st->udp);
    assert_int_equal(poll(&pfd, 1, RECV_TIMEOUT_MS), 1);
    assert_int_equal(srudpn_read_msg(st->udp, 0, &msg), SR_ERR_OK);
    assert_payload(msg);
    srudpn_msg_free(msg);

    /* nothing else */
    assert_int_equal(srudpn_read_msg(st->udp, 0, &msg), SR_ERR_TIME_OUT);
    assert_null(msg);
}

/**
 * @brief Test: segments received out of order are reassembled, a duplicate segment is dropped.
 */
static void
test_segments(void **state)
{
    struct state *st = *state;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    uint32_t len = strlen(XML_PAYLOAD), third = len / 3;

    /* out of order, segment 0 duplicated */
    seg_send(st, 1, 2, 1, XML_PAYLOAD + 2 * third, len - 2 * third);
    seg_send(st, 1, 0, 0, XML_PAYLOAD, third);
    seg_send(st, 1, 0, 0, XML_PAYLOAD, third);
    seg_send(st, 1, 1, 0, XML_PAYLOAD + third, third);

    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->segmented, 1);
    assert_int_equal(srudpn_msg_get_hdr(msg)->segment_num, 0);
    assert_int_equal(srudpn_msg_get_hdr(msg)->header_len, 16);
    assert_payload(msg);
    assert_notif(st, msg);
    srudpn_msg_free(msg);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.datagrams, 4);
    assert_int_equal(stats.dup_segments, 1);
    assert_int_equal(stats.messages, 1);
}

/**
 * @brief Test: segments of two publishers with the same publisher and message ID are not mixed.
 */
static void
test_segments_sources(void **state)
{
    struct state *st = *state;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    uint32_t len = strlen(XML_PAYLOAD), half = len / 2;
    char addr[SRUDPN_ADDR_STRLEN];
    uint16_t src_port[2];
    int fd2, i;

    /* a second publisher with the same publisher ID and message IDs, on another port */
    fd2 = socket(AF_INET, SOCK_DGRAM, 0);
    assert_int_not_equal(fd2, -1);

    /* interleaved segments of both */
    seg_send_from(st, st->fd, 1, 0, 0, XML_PAYLOAD, half);
    seg_send_from(st, fd2, 1, 0, 0, XML_PAYLOAD, half);
    seg_send_from(st, st->fd, 1, 1, 1, XML_PAYLOAD + half, len - half);
    seg_send_from(st, fd2, 1, 1, 1, XML_PAYLOAD + half, len - half);

    for (i = 0; i < 2; ++i) {
        assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
        assert_payload(msg);
        srudpn_msg_get_source(msg, addr, &src_port[i]);
        srudpn_msg_free(msg);
    }
    assert_int_not_equal(src_port[0], src_port[1]);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.dup_segments, 0);
    assert_int_equal(stats.messages, 2);

    close(fd2);
}

/**
 * @brief Test: inconsistent segments drop their message, so do too many incomplete messages.
 */
static void
test_inconsistent_segments(void **state)
{
    struct state *st = *state;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    uint32_t i;

    /* a segment past the last one drops the message */
    seg_send(st, 1, 1, 1, "b", 1);
    seg_send(st, 1, 2, 0, "c", 1);
    seg_send(st, 1, 0, 0, "a", 1);

    /* a last segment before an already received one drops the message */
    seg_send(st, 2, 3, 0, "d", 1);
    seg_send(st, 2, 1, 1, "b", 1);

    /* more incomplete messages than can be reassembled at once */
    for (i = 0; i < 17; ++i) {
        seg_send(st, 100 + i, 1, 0, "b", 1);
    }

    assert_int_equal(srudpn_read_msg(st->udp, QUIET_TIMEOUT_MS, &msg), SR_ERR_TIME_OUT);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.malformed, 2);
    assert_int_equal(stats.reasm_discarded, 2);
    assert_int_equal(stats.messages, 0);
}

/**
 * @brief Test: a full reassembly table drops the least recently active message, not an active one.
 */
static void
test_evict_inactive(void **state)
{
    struct state *st = *state;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;
    uint32_t len = strlen(XML_PAYLOAD), third = len / 3, i;

    /* a message, then incomplete messages filling the rest of the table */
    seg_send(st, 1, 0, 0, XML_PAYLOAD, third);
    for (i = 0; i < 15; ++i) {
        seg_send(st, 100 + i, 1, 0, "b", 1);
    }

    /* the first message keeps receiving segments, so another new message evicts an incomplete one */
    seg_send(st, 1, 1, 0, XML_PAYLOAD + third, third);
    seg_send(st, 200, 1, 0, "b", 1);

    seg_send(st, 1, 2, 1, XML_PAYLOAD + 2 * third, len - 2 * third);
    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->message_id, 1);
    assert_payload(msg);
    srudpn_msg_free(msg);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.reasm_discarded, 1);
}

/**
 * @brief Test: invalid datagrams are dropped and counted without stopping the collector.
 */
static void
test_invalid(void **state)
{
    struct state *st = *state;
    uint8_t buf[512] = {0};
    const uint8_t opt_len0[] = {1, 0, 0, 0}, opt_unknown[] = {2, 4, 0, 0}, opt_seg_len[] = {1, 6, 0, 0, 0, 0},
            opt_seg_twice[] = {1, 4, 0, 1, 1, 4, 0, 1};
    uint32_t len;
    srudpn_msg_t *msg;
    srudpn_stats_t stats;

    /* malformed: shorter than the header */
    dgram_send(st, buf, 11);

    /* malformed: Header Len shorter than the fixed header */
    len = dgram_build(buf, 0x22, 12, NULL, 1, "x", 1);
    buf[1] = 8;
    dgram_send(st, buf, len);

    /* malformed: Header Len past the datagram */
    len = dgram_build(buf, 0x22, 12, NULL, 1, "x", 1);
    buf[1] = 40;
    dgram_send(st, buf, len);

    /* malformed: Message Length not matching the datagram */
    len = dgram_build(buf, 0x22, 12, NULL, 1, "x", 1);
    buf[3] = 50;
    dgram_send(st, buf, len);

    /* malformed: no data after the header */
    dgram_send(st, buf, dgram_build(buf, 0x22, 12, NULL, 1, "", 0));

    /* malformed: zero option length */
    dgram_send(st, buf, dgram_build(buf, 0x22, 16, opt_len0, 1, "x", 1));

    /* malformed: segmentation option of a wrong length */
    dgram_send(st, buf, dgram_build(buf, 0x22, 18, opt_seg_len, 1, "x", 1));

    /* malformed: segmentation option twice */
    dgram_send(st, buf, dgram_build(buf, 0x22, 20, opt_seg_twice, 1, "x", 1));

    /* unsupported: version 2 */
    dgram_send(st, buf, dgram_build(buf, 0x42, 12, NULL, 1, "x", 1));

    /* unsupported: reserved media type */
    dgram_send(st, buf, dgram_build(buf, 0x20, 12, NULL, 1, "x", 1));

    /* unsupported: unknown option */
    dgram_send(st, buf, dgram_build(buf, 0x22, 16, opt_unknown, 1, "x", 1));

    /* a valid message after all of them */
    dgram_send(st, buf, dgram_build(buf, 0x22, 12, NULL, 2, XML_PAYLOAD, strlen(XML_PAYLOAD)));

    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->message_id, 2);
    srudpn_msg_free(msg);

    stats = srudpn_get_stats(st->udp);
    assert_int_equal(stats.datagrams, 12);
    assert_int_equal(stats.malformed, 8);
    assert_int_equal(stats.unsupported, 3);
    assert_int_equal(stats.messages, 1);
}

/**
 * @brief Test: parsing fails for a private media type, CBOR without libyang support or invalid, and an unknown envelope.
 */
static void
test_parse_unsupported(void **state)
{
    struct state *st = *state;
    uint8_t buf[512];
    const char *json_unknown = "{\"ietf-yp-notification:envelope\":{\"event-time\":\"2026-10-15T10:00:00Z\"}}";
    srudpn_msg_t *msg;
    srudpn_notif_t *notif;

    /* private media type */
    dgram_send(st, buf, dgram_build(buf, 0x32, 12, NULL, 1, XML_PAYLOAD, strlen(XML_PAYLOAD)));
    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->s_flag, 1);
    assert_int_equal(srudpn_msg_get_media_type(msg), SRUDPN_MT_PRIVATE);
    assert_payload(msg);
    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &notif), SR_ERR_UNSUPPORTED);
    assert_null(notif);
    srudpn_msg_free(msg);

    /* CBOR */
    dgram_send(st, buf, dgram_build(buf, 0x23, 12, NULL, 2, "x", 1));
    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_media_type(msg), SRUDPN_MT_CBOR);
#ifdef LY_HAVE_CBOR
    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &notif), SR_ERR_LY);
#else
    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &notif), SR_ERR_UNSUPPORTED);
#endif /* LY_HAVE_CBOR */
    srudpn_msg_free(msg);

    /* unknown envelope, rejected by libyang */
    dgram_send(st, buf, dgram_build(buf, 0x21, 12, NULL, 3, json_unknown, strlen(json_unknown)));
    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &notif), SR_ERR_LY);
    srudpn_msg_free(msg);
}

/**
 * @brief Encode a notification, send it and assert it is received unchanged.
 */
static void
roundtrip(struct state *st, srudpn_media_type_t media_type, uint16_t max_segment_size, int segmented)
{
    struct lyd_node *notif;
    srudpn_notif_t *recv_notif;
    struct timespec ts = {.tv_sec = 1760522400};
    uint8_t *payload;
    const uint8_t *recv_payload;
    uint32_t payload_len, recv_len;
    LYA_COUNT_T i;
    srudpn_dgram_t *dgrams;
    srudpn_msg_t *msg;
    struct iovec iov[2];
    struct msghdr mh = {0};

    assert_int_equal(lyd_new_path(NULL, st->ly_ctx, "/t:notif/leaf", "a long enough value to need segments", 0,
            &notif), LY_SUCCESS);
    assert_int_equal(lyd_new_path(notif, NULL, "/t:notif/num", "0", 0, NULL), LY_SUCCESS);
    assert_int_equal(srudpn_encode_notification(notif, &ts, media_type, &payload, &payload_len), SR_ERR_OK);
    if (media_type == SRUDPN_MT_CBOR) {
        /* the num leaf 0 puts a zero byte in the payload, it must not be handled as a string */
        assert_non_null(memchr(payload, 0, payload_len));
    }
    assert_int_equal(srudpn_build_dgrams(media_type, 5, 77, payload, payload_len, max_segment_size, &dgrams),
            SR_ERR_OK);
    if (segmented) {
        assert_true(LYA_COUNT(dgrams) > 1);
    } else {
        assert_int_equal(LYA_COUNT(dgrams), 1);
    }

    /* send the datagrams in reverse order */
    mh.msg_name = &st->addr;
    mh.msg_namelen = sizeof st->addr;
    mh.msg_iov = iov;
    mh.msg_iovlen = 2;
    for (i = LYA_COUNT(dgrams); i; --i) {
        iov[0].iov_base = dgrams[i - 1].hdr;
        iov[0].iov_len = dgrams[i - 1].hdr_len;
        iov[1].iov_base = (void *)dgrams[i - 1].data;
        iov[1].iov_len = dgrams[i - 1].data_len;
        assert_int_equal(sendmsg(st->fd, &mh, 0), dgrams[i - 1].hdr_len + dgrams[i - 1].data_len);
    }
    LYA_FREE(dgrams);

    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_hdr(msg)->media_type, media_type);
    assert_int_equal(srudpn_msg_get_hdr(msg)->publisher_id, 5);
    assert_int_equal(srudpn_msg_get_hdr(msg)->message_id, 77);
    srudpn_msg_get_payload(msg, &recv_payload, &recv_len);
    assert_int_equal(recv_len, payload_len);
    assert_memory_equal(recv_payload, payload, payload_len);
    free(payload);

    assert_int_equal(srudpn_msg_parse(msg, st->ly_ctx, &recv_notif), SR_ERR_OK);
    assert_int_equal(srudpn_notif_get_event_time(recv_notif)->tv_sec, ts.tv_sec);
    assert_int_equal(lyd_compare_single(notif, srudpn_notif_get_tree(recv_notif), LYD_COMPARE_FULL_RECURSION),
            LY_SUCCESS);
    srudpn_notif_free(recv_notif);
    srudpn_msg_free(msg);

    lyd_free_all(notif);
}

/**
 * @brief Test: an encoded notification is received and parsed unchanged, unsegmented and segmented.
 */
static void
test_roundtrip(void **state)
{
    struct state *st = *state;

    roundtrip(st, SRUDPN_MT_XML, 0, 0);
    roundtrip(st, SRUDPN_MT_JSON, 0, 0);
    roundtrip(st, SRUDPN_MT_XML, 1400, 0);
    roundtrip(st, SRUDPN_MT_XML, 40, 1);
    roundtrip(st, SRUDPN_MT_JSON, 40, 1);
#ifdef LY_HAVE_CBOR
    roundtrip(st, SRUDPN_MT_CBOR, 0, 0);
    roundtrip(st, SRUDPN_MT_CBOR, 40, 1);
#endif /* LY_HAVE_CBOR */
}

#ifdef LY_HAVE_CBOR

/**
 * @brief Test: a CBOR notification with eventTime after the notification is parsed.
 */
static void
test_parse_cbor(void **state)
{
    struct state *st = *state;
    uint8_t buf[512];
    srudpn_msg_t *msg;
    const char cbor[] =
            "\xA1\x78\x1A" "ietf-restconf:notification"
            "\xA2"
            "\x67" "t:notif" "\xA1" "\x64" "leaf" "\x65" "value"
            "\x69" "eventTime" "\x74" "2026-10-15T10:00:00Z";

    dgram_send(st, buf, dgram_build(buf, 0x23, 12, NULL, 1, cbor, sizeof cbor - 1));
    assert_int_equal(srudpn_read_msg(st->udp, RECV_TIMEOUT_MS, &msg), SR_ERR_OK);
    assert_int_equal(srudpn_msg_get_media_type(msg), SRUDPN_MT_CBOR);
    assert_notif(st, msg);
    srudpn_msg_free(msg);
}

#endif /* LY_HAVE_CBOR */

/**
 * @brief Test: the encoder rejects payloads and segment sizes that do not fit the header fields.
 */
static void
test_encode_limits(void **state)
{
    struct state *st = *state;
    uint8_t *payload;
    srudpn_dgram_t *dgrams;
    uint32_t len;
    struct lyd_node *notif;

    payload = calloc(1, 65536);
    assert_non_null(payload);

    /* empty payload */
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 0, 0, &dgrams), SR_ERR_INVAL_ARG);

    /* largest unsegmented message */
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 65535 - 12, 0, &dgrams), SR_ERR_OK);
    assert_int_equal(LYA_COUNT(dgrams), 1);
    assert_int_equal(dgrams[0].hdr[2], 0xFF);
    assert_int_equal(dgrams[0].hdr[3], 0xFF);
    LYA_FREE(dgrams);

    /* one octet more */
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 65535 - 11, 0, &dgrams), SR_ERR_INVAL_ARG);
    assert_null(dgrams);

    /* segments that cannot fit the header */
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 100, 16, &dgrams), SR_ERR_INVAL_ARG);

    /* more than 32768 segments of 1 octet */
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 32768, 17, &dgrams), SR_ERR_OK);
    assert_int_equal(LYA_COUNT(dgrams), 32768);
    assert_int_equal(dgrams[32767].hdr[14], 0xFF);
    assert_int_equal(dgrams[32767].hdr[15], 0xFF);
    LYA_FREE(dgrams);
    assert_int_equal(srudpn_build_dgrams(SRUDPN_MT_JSON, 1, 1, payload, 32769, 17, &dgrams), SR_ERR_INVAL_ARG);

    free(payload);

    /* unsupported media types */
    assert_int_equal(lyd_new_path(NULL, st->ly_ctx, "/t:notif/leaf", "value", 0, &notif), LY_SUCCESS);
    assert_int_equal(srudpn_encode_notification(notif, &(struct timespec) {0}, SRUDPN_MT_PRIVATE, &payload, &len),
            SR_ERR_UNSUPPORTED);
    assert_null(payload);
#ifndef LY_HAVE_CBOR
    assert_int_equal(srudpn_encode_notification(notif, &(struct timespec) {0}, SRUDPN_MT_CBOR, &payload, &len),
            SR_ERR_UNSUPPORTED);
    assert_null(payload);
#endif /* LY_HAVE_CBOR */
    lyd_free_all(notif);
}

int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_unsegmented, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_no_wait, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_segments, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_segments_sources, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_inconsistent_segments, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_evict_inactive, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_invalid, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_parse_unsupported, setup_f, teardown_f),
        cmocka_unit_test_setup_teardown(test_roundtrip, setup_f, teardown_f),
#ifdef LY_HAVE_CBOR
        cmocka_unit_test_setup_teardown(test_parse_cbor, setup_f, teardown_f),
#endif /* LY_HAVE_CBOR */
        cmocka_unit_test(test_encode_limits),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
