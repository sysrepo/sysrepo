/**
 * @file udp_notif.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief UDP-Notif (draft-ietf-netconf-udp-notif) collector and encoder functions
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

#include "udp_notif.h"

#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "log.h"
#include "ly_wrap.h"
#include "udp_notif_common.h"

/**
 * @brief Parse and validate the header of a received datagram.
 *
 * @param[in] udp Collector counting an invalid datagram.
 * @param[in] data Received datagram.
 * @param[in] len Length of @p data.
 * @param[out] hdr Parsed header.
 * @return 0 on a valid header, 1 if the datagram is to be dropped.
 */
static int
srudpn_hdr_parse(srudpn_t *udp, const uint8_t *data, uint32_t len, srudpn_hdr_t *hdr)
{
    const char *reason;
    uint32_t off;
    uint8_t opt_type, opt_len;

    memset(hdr, 0, sizeof *hdr);

    if (len < SRUDPN_HDR_SIZE) {
        reason = "shorter than the header";
        goto malformed;
    }

    /* Ver (3 bits), S-flag (1 bit), MT (4 bits), Header Len, Message Length, Publisher ID, Message ID */
    hdr->version = data[0] >> 5;
    hdr->s_flag = (data[0] >> 4) & 0x01;
    hdr->media_type = data[0] & 0x0F;
    hdr->header_len = data[1];
    hdr->message_len = ((uint16_t)data[2] << 8) | data[3];
    hdr->publisher_id = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) | ((uint32_t)data[6] << 8) | data[7];
    hdr->message_id = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) | ((uint32_t)data[10] << 8) | data[11];

    if (hdr->version != SRUDPN_VERSION) {
        reason = "unsupported version";
        goto unsupported;
    }
    if ((hdr->header_len < SRUDPN_HDR_SIZE) || (hdr->header_len > len)) {
        reason = "invalid Header Len";
        goto malformed;
    }
    if (hdr->message_len != len) {
        reason = "Message Length not matching the datagram";
        goto malformed;
    }
    if (hdr->header_len == len) {
        reason = "no data";
        goto malformed;
    }
    if (!hdr->s_flag && !hdr->media_type) {
        reason = "reserved media type";
        goto unsupported;
    }

    /* options, each Type (8 bits), Length (8 bits, including Type and Length) and data */
    for (off = SRUDPN_HDR_SIZE; off < hdr->header_len; off += opt_len) {
        if (off + 2 > hdr->header_len) {
            reason = "truncated option";
            goto malformed;
        }
        opt_type = data[off];
        opt_len = data[off + 1];
        if ((opt_len < 2) || (off + opt_len > hdr->header_len)) {
            reason = "invalid option length";
            goto malformed;
        }

        if (opt_type != SRUDPN_OPT_SEGMENTATION) {
            reason = "unsupported option";
            goto unsupported;
        }
        if ((opt_len != SRUDPN_OPT_SEGMENTATION_SIZE) || hdr->segmented) {
            reason = "invalid segmentation option";
            goto malformed;
        }

        /* Segment Number (15 bits), L-flag (1 bit) */
        hdr->segmented = 1;
        hdr->segment_num = (((uint16_t)data[off + 2] << 8) | data[off + 3]) >> 1;
        hdr->last_segment = data[off + 3] & 0x01;
    }

    return 0;

malformed:
    SR_LOG_DBG("UDP-Notif datagram dropped (%s).", reason);
    ++udp->stats.malformed;
    return 1;

unsupported:
    SR_LOG_DBG("UDP-Notif datagram dropped (%s).", reason);
    ++udp->stats.unsupported;
    return 1;
}

/**
 * @brief Compare the addresses and ports of two datagram sources.
 *
 * @param[in] src1 First source.
 * @param[in] src2 Second source.
 * @return 1 if equal, 0 otherwise.
 */
static int
srudpn_src_eq(const struct sockaddr_storage *src1, const struct sockaddr_storage *src2)
{
    const struct sockaddr_in *sin1 = (const struct sockaddr_in *)src1, *sin2 = (const struct sockaddr_in *)src2;
    const struct sockaddr_in6 *sin6_1 = (const struct sockaddr_in6 *)src1, *sin6_2 = (const struct sockaddr_in6 *)src2;

    if (src1->ss_family != src2->ss_family) {
        return 0;
    }

    if (src1->ss_family == AF_INET) {
        return (sin1->sin_port == sin2->sin_port) && (sin1->sin_addr.s_addr == sin2->sin_addr.s_addr);
    }
    return (sin6_1->sin6_port == sin6_2->sin6_port) &&
           !memcmp(&sin6_1->sin6_addr, &sin6_2->sin6_addr, sizeof sin6_1->sin6_addr);
}

/**
 * @brief Create a message with an allocated payload to be filled.
 *
 * @param[in] hdr Header of the message.
 * @param[in] payload_len Length of the payload.
 * @param[in] src Source of the message.
 * @param[out] msg Created message.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srudpn_msg_new(const srudpn_hdr_t *hdr, uint32_t payload_len, const struct sockaddr_storage *src, srudpn_msg_t **msg)
{
    sr_error_info_t *err_info = NULL;
    const struct sockaddr_in6 *sin6 = (const struct sockaddr_in6 *)src;
    struct sockaddr_in *sin;

    *msg = calloc(1, sizeof **msg);
    SR_CHECK_MEM_GOTO(!*msg, err_info, cleanup);

    (*msg)->payload = malloc(payload_len);
    SR_CHECK_MEM_GOTO(!(*msg)->payload, err_info, cleanup);

    (*msg)->hdr = *hdr;
    (*msg)->payload_len = payload_len;
    if ((src->ss_family == AF_INET6) && IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
        /* IPv4 source received on a dual-stack socket */
        sin = (struct sockaddr_in *)&(*msg)->src;
        sin->sin_family = AF_INET;
        sin->sin_port = sin6->sin6_port;
        memcpy(&sin->sin_addr, &sin6->sin6_addr.s6_addr[12], sizeof sin->sin_addr);
    } else {
        (*msg)->src = *src;
    }

cleanup:
    if (err_info) {
        srudpn_msg_free(*msg);
        *msg = NULL;
    }
    return err_info;
}

/**
 * @brief Remove a message being reassembled.
 *
 * @param[in] udp Collector to use.
 * @param[in] idx Index of the message in the reassembled messages.
 */
static void
srudpn_reasm_del(srudpn_t *udp, LYA_COUNT_T idx)
{
    struct srudpn_seg *seg;

    LYA_FOR_EACH(udp->reasms[idx].segs, seg) {
        free(seg->data);
    }
    LYA_FREE(udp->reasms[idx].segs);

    if (idx < LYA_COUNT(udp->reasms) - 1) {
        udp->reasms[idx] = udp->reasms[LYA_COUNT(udp->reasms) - 1];
    }
    LYA_DECREMENT(udp->reasms);
}

/**
 * @brief Drop the least recently active message being reassembled.
 *
 * @param[in] udp Collector to use.
 * @param[in,out] keep Optional message not to drop, updated if it was moved.
 * @return 0 if a message was dropped, 1 if there was none to drop.
 */
static int
srudpn_reasm_evict(srudpn_t *udp, struct srudpn_reasm **keep)
{
    LYA_COUNT_T i, lru = LYA_COUNT(udp->reasms);

    LYA_FOR(udp->reasms, i) {
        if (keep && (&udp->reasms[i] == *keep)) {
            continue;
        }
        if ((lru == LYA_COUNT(udp->reasms)) || (sr_time_cmp(&udp->reasms[i].last_ts, &udp->reasms[lru].last_ts) < 0)) {
            lru = i;
        }
    }
    if (lru == LYA_COUNT(udp->reasms)) {
        return 1;
    }

    SR_LOG_DBG("UDP-Notif message %" PRIu32 " of publisher %" PRIu32 " evicted before being reassembled.",
            udp->reasms[lru].message_id, udp->reasms[lru].publisher_id);
    if (keep && (*keep == &udp->reasms[LYA_COUNT(udp->reasms) - 1])) {
        /* the last message is moved into the place of the dropped one */
        *keep = &udp->reasms[lru];
    }
    srudpn_reasm_del(udp, lru);
    ++udp->stats.reasm_discarded;
    return 0;
}

/**
 * @brief Drop the messages whose reassembly timed out.
 *
 * @param[in] udp Collector to use.
 * @param[in] now Current monotonic time.
 */
static void
srudpn_reasm_drop_expired(srudpn_t *udp, const struct timespec *now)
{
    LYA_COUNT_T i;

    /* backwards, a removed message is replaced by the last one */
    i = LYA_COUNT(udp->reasms);
    while (i) {
        --i;
        if (sr_time_sub_ms(now, &udp->reasms[i].first_ts) >= SRUDPN_REASM_TIMEOUT_MS) {
            SR_LOG_DBG("UDP-Notif message %" PRIu32 " of publisher %" PRIu32 " not reassembled in time, dropped.",
                    udp->reasms[i].message_id, udp->reasms[i].publisher_id);
            srudpn_reasm_del(udp, i);
            ++udp->stats.reasm_discarded;
        }
    }
}

/**
 * @brief Find the message a segment belongs to, create it if it is new.
 *
 * @param[in] udp Collector to use.
 * @param[in] hdr Header of the segment.
 * @param[in] src Source of the segment.
 * @param[in] now Current monotonic time.
 * @param[out] reasm Message being reassembled.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srudpn_reasm_get(srudpn_t *udp, const srudpn_hdr_t *hdr, const struct sockaddr_storage *src,
        const struct timespec *now, struct srudpn_reasm **reasm)
{
    sr_error_info_t *err_info = NULL;
    LYA_COUNT_T i;

    LYA_FOR(udp->reasms, i) {
        if ((udp->reasms[i].publisher_id == hdr->publisher_id) && (udp->reasms[i].message_id == hdr->message_id) &&
                srudpn_src_eq(&udp->reasms[i].src, src)) {
            *reasm = &udp->reasms[i];
            goto cleanup;
        }
    }

    if (LYA_COUNT(udp->reasms) == SRUDPN_MAX_PENDING) {
        srudpn_reasm_evict(udp, NULL);
    }

    LYA_ADD_ITEM(udp->reasms, *reasm, SR_ERRINFO_MEM(&err_info); goto cleanup);
    (*reasm)->publisher_id = hdr->publisher_id;
    (*reasm)->message_id = hdr->message_id;
    (*reasm)->src = *src;
    (*reasm)->first_ts = *now;
    (*reasm)->last = -1;

cleanup:
    return err_info;
}

/**
 * @brief Make room for more memory of a message within the budget of all the messages being reassembled.
 *
 * @param[in] udp Collector to use.
 * @param[in,out] reasm Message to grow, updated if it was moved.
 * @param[in] size Memory to add to @p reasm.
 * @return 0 if it fits, 1 if @p reasm was dropped.
 */
static int
srudpn_reasm_fit(srudpn_t *udp, struct srudpn_reasm **reasm, uint32_t size)
{
    LYA_COUNT_T i;
    uint32_t total;

    while (1) {
        total = size;
        LYA_FOR(udp->reasms, i) {
            total += udp->reasms[i].size;
        }
        if (total <= SRUDPN_REASM_MAX_BYTES) {
            return 0;
        }

        /* drop the least recently active other message */
        if (srudpn_reasm_evict(udp, reasm)) {
            break;
        }
    }

    SR_LOG_DBG("UDP-Notif message %" PRIu32 " of publisher %" PRIu32 " too large to reassemble, dropped.",
            (*reasm)->message_id, (*reasm)->publisher_id);
    srudpn_reasm_del(udp, *reasm - udp->reasms);
    ++udp->stats.reasm_discarded;
    return 1;
}

/**
 * @brief Create the message from all its received segments and stop reassembling it.
 *
 * @param[in] udp Collector to use.
 * @param[in] reasm Message with all the segments received.
 * @param[out] msg Created message.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srudpn_reasm_finish(srudpn_t *udp, struct srudpn_reasm *reasm, srudpn_msg_t **msg)
{
    sr_error_info_t *err_info = NULL;
    struct srudpn_seg *seg;
    uint32_t payload_len = 0, off = 0;

    LYA_FOR_EACH(reasm->segs, seg) {
        payload_len += seg->len;
    }
    if ((err_info = srudpn_msg_new(&reasm->hdr, payload_len, &reasm->src, msg))) {
        goto cleanup;
    }
    LYA_FOR_EACH(reasm->segs, seg) {
        memcpy((*msg)->payload + off, seg->data, seg->len);
        off += seg->len;
    }

    srudpn_reasm_del(udp, reasm - udp->reasms);

cleanup:
    return err_info;
}

/**
 * @brief Add a segment to its message, completing it once all the segments were received.
 *
 * @param[in] udp Collector to use.
 * @param[in] hdr Header of the segment.
 * @param[in] data Segment data.
 * @param[in] len Length of @p data.
 * @param[in] src Source of the segment.
 * @param[in] now Current monotonic time.
 * @param[out] msg Completed message, NULL if not complete yet.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srudpn_seg_add(srudpn_t *udp, const srudpn_hdr_t *hdr, const uint8_t *data, uint16_t len,
        const struct sockaddr_storage *src, const struct timespec *now, srudpn_msg_t **msg)
{
    sr_error_info_t *err_info = NULL;
    struct srudpn_reasm *reasm;
    struct srudpn_seg *seg;
    uint32_t size;
    uint16_t seg_num = hdr->segment_num;

    if ((err_info = srudpn_reasm_get(udp, hdr, src, now, &reasm))) {
        goto cleanup;
    }

    if ((seg_num < LYA_COUNT(reasm->segs)) && reasm->segs[seg_num].data) {
        SR_LOG_DBG("Duplicate segment %" PRIu16 " of UDP-Notif message %" PRIu32 " dropped.", seg_num,
                reasm->message_id);
        ++udp->stats.dup_segments;
        goto cleanup;
    }

    /* a second last segment or one past the last, or a last segment before an already received one */
    if (((reasm->last > -1) && (hdr->last_segment || (seg_num > reasm->last))) ||
            (hdr->last_segment && (LYA_COUNT(reasm->segs) > (LYA_COUNT_T)seg_num + 1))) {
        SR_LOG_DBG("UDP-Notif message %" PRIu32 " with inconsistent segments dropped.", reasm->message_id);
        srudpn_reasm_del(udp, reasm - udp->reasms);
        ++udp->stats.malformed;
        goto cleanup;
    }

    /* the segment data and the growth of the segment array */
    size = len;
    if (seg_num >= LYA_COUNT(reasm->segs)) {
        size += ((uint32_t)seg_num + 1 - LYA_COUNT(reasm->segs)) * sizeof *reasm->segs;
    }
    if (srudpn_reasm_fit(udp, &reasm, size)) {
        goto cleanup;
    }

    /* store the segment */
    if (seg_num >= LYA_COUNT(reasm->segs)) {
        LYA_NEW(reasm->segs, (LYA_COUNT_T)seg_num + 1, SR_ERRINFO_MEM(&err_info); goto cleanup);
    }
    seg = &reasm->segs[seg_num];
    seg->data = malloc(len);
    SR_CHECK_MEM_GOTO(!seg->data, err_info, cleanup);
    memcpy(seg->data, data, len);
    seg->len = len;
    ++reasm->received;
    reasm->size += size;
    reasm->last_ts = *now;
    if (!seg_num) {
        reasm->hdr = *hdr;
    }
    if (hdr->last_segment) {
        reasm->last = seg_num;
    }

    if ((reasm->last > -1) && (reasm->received == reasm->last + 1)) {
        err_info = srudpn_reasm_finish(udp, reasm, msg);
    }

cleanup:
    return err_info;
}

/**
 * @brief Process a received datagram.
 *
 * @param[in] udp Collector the datagram was received by.
 * @param[in] buf Received datagram.
 * @param[in] len Length of @p buf.
 * @param[in] src Source of the datagram.
 * @param[out] msg Completed message, NULL if none.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srudpn_dgram_process(srudpn_t *udp, const uint8_t *buf, uint32_t len, const struct sockaddr_storage *src,
        srudpn_msg_t **msg)
{
    sr_error_info_t *err_info = NULL;
    struct timespec now;
    srudpn_hdr_t hdr;
    const uint8_t *data;
    uint32_t data_len;

    ++udp->stats.datagrams;

    /* a late segment of a timed out message starts a new one */
    sr_timeouttime_get(&now, 0);
    srudpn_reasm_drop_expired(udp, &now);

    if (srudpn_hdr_parse(udp, buf, len, &hdr)) {
        goto cleanup;
    }

    data = buf + hdr.header_len;
    data_len = len - hdr.header_len;

    if (hdr.segmented) {
        err_info = srudpn_seg_add(udp, &hdr, data, data_len, src, &now, msg);
        goto cleanup;
    }

    if ((err_info = srudpn_msg_new(&hdr, data_len, src, msg))) {
        goto cleanup;
    }
    memcpy((*msg)->payload, data, data_len);

cleanup:
    if (*msg) {
        ++udp->stats.messages;
    }
    return err_info;
}

API int
srudpn_open(const char *address, uint16_t port, srudpn_t **udp)
{
    sr_error_info_t *err_info = NULL;
    struct addrinfo hints = {0}, *ai = NULL;
    struct sockaddr_storage sa;
    socklen_t sa_len;
    char port_str[6];
    int r, fd = -1, opt;

    SR_CHECK_ARG_APIRET(!udp, NULL, err_info);

    *udp = NULL;

    if (!address) {
        /* dual-stack, IPv4 only if IPv6 is disabled */
        address = "::";
        fd = socket(AF_INET6, SOCK_DGRAM | SOCK_CLOEXEC, 0);
        if (fd > -1) {
            close(fd);
            fd = -1;
        } else if (errno == EAFNOSUPPORT) {
            address = "0.0.0.0";
        }
    }

    /* resolve the numeric local address */
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
    sprintf(port_str, "%" PRIu16, port);
    if ((r = getaddrinfo(address, port_str, &hints, &ai))) {
        sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "Invalid UDP-Notif collector address \"%s\" (%s).", address,
                gai_strerror(r));
        goto cleanup;
    }

    fd = socket(ai->ai_family, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (fd == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "socket");
        goto cleanup;
    }

    if (ai->ai_family == AF_INET6) {
        /* receive IPv4 datagrams as well */
        opt = 0;
        if (setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof opt)) {
            SR_ERRINFO_SYSERRNO(&err_info, "setsockopt");
            goto cleanup;
        }
    }

    /* best-effort larger receive buffer for segment bursts, the kernel may cap it */
    opt = SRUDPN_RCVBUF_SIZE;
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &opt, sizeof opt)) {
        SR_LOG_WRN("Enlarging the UDP-Notif collector receive buffer failed (%s).", strerror(errno));
    }

    if (bind(fd, ai->ai_addr, ai->ai_addrlen)) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Binding UDP-Notif collector to \"%s\" port %" PRIu16 " failed (%s).",
                address, port, strerror(errno));
        goto cleanup;
    }

    /* learn the bound port */
    sa_len = sizeof sa;
    if (getsockname(fd, (struct sockaddr *)&sa, &sa_len)) {
        SR_ERRINFO_SYSERRNO(&err_info, "getsockname");
        goto cleanup;
    }

    *udp = calloc(1, sizeof **udp);
    SR_CHECK_MEM_GOTO(!*udp, err_info, cleanup);
    (*udp)->fd = fd;
    if (sa.ss_family == AF_INET6) {
        (*udp)->port = ntohs(((struct sockaddr_in6 *)&sa)->sin6_port);
    } else {
        (*udp)->port = ntohs(((struct sockaddr_in *)&sa)->sin_port);
    }
    fd = -1;

cleanup:
    if (ai) {
        freeaddrinfo(ai);
    }
    if (fd > -1) {
        close(fd);
    }
    return sr_api_ret(NULL, err_info);
}

API int
srudpn_get_fd(const srudpn_t *udp)
{
    return udp ? udp->fd : -1;
}

API uint16_t
srudpn_get_port(const srudpn_t *udp)
{
    return udp ? udp->port : 0;
}

API srudpn_stats_t
srudpn_get_stats(const srudpn_t *udp)
{
    srudpn_stats_t stats = {0};

    if (udp) {
        stats = udp->stats;
    }
    return stats;
}

API void
srudpn_close(srudpn_t *udp)
{
    if (!udp) {
        return;
    }

    while (LYA_COUNT(udp->reasms)) {
        srudpn_reasm_del(udp, 0);
    }
    LYA_FREE(udp->reasms);
    close(udp->fd);
    free(udp);
}

API int
srudpn_read_msg(srudpn_t *udp, int32_t timeout_ms, srudpn_msg_t **msg)
{
    sr_error_info_t *err_info = NULL;
    uint8_t buf[SRUDPN_MAX_DGRAM_SIZE];
    struct sockaddr_storage src;
    socklen_t src_len;
    struct timespec deadline, now;
    struct pollfd pfd = {0};
    ssize_t len;
    int r, wait_ms;

    SR_CHECK_ARG_APIRET(!udp || (timeout_ms < -1) || !msg, NULL, err_info);

    *msg = NULL;

    if (timeout_ms > 0) {
        sr_timeouttime_get(&deadline, timeout_ms);
    }
    pfd.fd = udp->fd;
    pfd.events = POLLIN;

    while (1) {
        /* the time to wait, the remaining one checked before every datagram */
        wait_ms = timeout_ms;
        if (timeout_ms > 0) {
            sr_timeouttime_get(&now, 0);
            wait_ms = sr_time_sub_ms(&deadline, &now);
            if (wait_ms < 0) {
                goto cleanup;
            }
        }

        src_len = sizeof src;
        len = recvfrom(udp->fd, buf, sizeof buf, MSG_DONTWAIT, (struct sockaddr *)&src, &src_len);
        if (len == -1) {
            if ((errno != EAGAIN) && (errno != EWOULDBLOCK)) {
                SR_ERRINFO_SYSERRNO(&err_info, "recvfrom");
                goto cleanup;
            }

            /* nothing queued, wait for more, a signal ends the wait like a timeout */
            if (!wait_ms) {
                goto cleanup;
            }
            r = poll(&pfd, 1, wait_ms);
            if (!r || ((r == -1) && (errno == EINTR))) {
                goto cleanup;
            } else if (r == -1) {
                SR_ERRINFO_SYSERRNO(&err_info, "poll");
                goto cleanup;
            }
            continue;
        }

        /* process the datagram, done once it completes a message */
        if ((err_info = srudpn_dgram_process(udp, buf, len, &src, msg))) {
            goto cleanup;
        }
        if (*msg) {
            goto cleanup;
        }
    }

cleanup:
    if (!err_info && !*msg) {
        return SR_ERR_TIME_OUT;
    }
    return sr_api_ret(NULL, err_info);
}

API const srudpn_hdr_t *
srudpn_msg_get_hdr(const srudpn_msg_t *msg)
{
    return msg ? &msg->hdr : NULL;
}

API srudpn_media_type_t
srudpn_msg_get_media_type(const srudpn_msg_t *msg)
{
    if (!msg) {
        return 0;
    }

    return msg->hdr.s_flag ? SRUDPN_MT_PRIVATE : msg->hdr.media_type;
}

API void
srudpn_msg_get_payload(const srudpn_msg_t *msg, const uint8_t **payload, uint32_t *payload_len)
{
    if (!msg || !payload || !payload_len) {
        return;
    }

    *payload = msg->payload;
    *payload_len = msg->payload_len;
}

API void
srudpn_msg_get_source(const srudpn_msg_t *msg, char *addr, uint16_t *port)
{
    socklen_t sa_len;

    if (!msg || !addr || !port) {
        return;
    }

    if (msg->src.ss_family == AF_INET6) {
        sa_len = sizeof(struct sockaddr_in6);
        *port = ntohs(((const struct sockaddr_in6 *)&msg->src)->sin6_port);
    } else {
        sa_len = sizeof(struct sockaddr_in);
        *port = ntohs(((const struct sockaddr_in *)&msg->src)->sin_port);
    }

    /* numeric address, a scoped IPv6 one with its interface */
    getnameinfo((const struct sockaddr *)&msg->src, sa_len, addr, SRUDPN_ADDR_STRLEN, NULL, 0, NI_NUMERICHOST);
}

API int
srudpn_msg_parse(const srudpn_msg_t *msg, const struct ly_ctx *ly_ctx, srudpn_notif_t **notif)
{
    sr_error_info_t *err_info = NULL;
    LYD_FORMAT format;
    enum lyd_type data_type;
    const struct lyd_node *node;
    char *str = NULL;

    SR_CHECK_ARG_APIRET(!msg || !ly_ctx || !notif, NULL, err_info);

    *notif = NULL;

    if (msg->hdr.s_flag) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Private UDP-Notif media type %" PRIu8 " is not supported.",
                msg->hdr.media_type);
        goto cleanup;
    }
    switch (msg->hdr.media_type) {
    case SRUDPN_MT_JSON:
        format = LYD_JSON;
        data_type = LYD_TYPE_NOTIF_RESTCONF;
        break;
    case SRUDPN_MT_XML:
        format = LYD_XML;
        data_type = LYD_TYPE_NOTIF_NETCONF;
        break;
    default:
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "UDP-Notif media type %" PRIu8 " is not supported.",
                msg->hdr.media_type);
        goto cleanup;
    }

    *notif = calloc(1, sizeof **notif);
    SR_CHECK_MEM_GOTO(!*notif, err_info, cleanup);

    /* the XML and JSON parsers read until a NUL even from a bounded input */
    str = strndup((const char *)msg->payload, msg->payload_len);
    SR_CHECK_MEM_GOTO(!str, err_info, cleanup);

    /* parse the RFC 5277 envelope and the notification */
    if ((err_info = sr_lyd_parse_op(ly_ctx, str, 0, format, data_type, &(*notif)->env, &(*notif)->tree))) {
        goto cleanup;
    }

    /* store the event time, already validated by the parser */
    LY_LIST_FOR(lyd_child((*notif)->env), node) {
        if (!node->schema && !strcmp(LYD_NAME(node), "eventTime")) {
            if ((err_info = sr_ly_time_str2ts(lyd_get_value(node), &(*notif)->event_time))) {
                goto cleanup;
            }
            break;
        }
    }

cleanup:
    free(str);
    if (err_info) {
        srudpn_notif_free(*notif);
        *notif = NULL;
    }
    return sr_api_ret(NULL, err_info);
}

API void
srudpn_msg_free(srudpn_msg_t *msg)
{
    if (!msg) {
        return;
    }

    free(msg->payload);
    free(msg);
}

API const struct lyd_node *
srudpn_notif_get_tree(const srudpn_notif_t *notif)
{
    return notif ? notif->tree : NULL;
}

API const struct lyd_node *
srudpn_notif_get_envelope(const srudpn_notif_t *notif)
{
    return notif ? notif->env : NULL;
}

API const struct timespec *
srudpn_notif_get_event_time(const srudpn_notif_t *notif)
{
    return notif ? &notif->event_time : NULL;
}

API void
srudpn_notif_free(srudpn_notif_t *notif)
{
    if (!notif) {
        return;
    }

    lyd_free_all(notif->env);
    lyd_free_all(notif->tree);
    free(notif);
}

API int
srudpn_encode_notification(const struct lyd_node *notif, const struct timespec *event_time, srudpn_media_type_t media_type,
        uint8_t **payload, uint32_t *payload_len)
{
    sr_error_info_t *err_info = NULL;
    char *event_time_str = NULL, *inner = NULL, *inner_end, *str = NULL;
    LYD_FORMAT format;
    int r;

    SR_CHECK_ARG_APIRET(!notif || !event_time || !payload || !payload_len, NULL, err_info);

    *payload = NULL;
    *payload_len = 0;

    switch (media_type) {
    case SRUDPN_MT_JSON:
        format = LYD_JSON;
        break;
    case SRUDPN_MT_XML:
        format = LYD_XML;
        break;
    default:
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "UDP-Notif media type %d is not supported.", (int)media_type);
        goto cleanup;
    }

    if ((err_info = sr_ly_time_ts2str(event_time, &event_time_str))) {
        goto cleanup;
    }

    /* without whitespace, the JSON object is spliced into the envelope */
    if ((err_info = sr_lyd_print_data(notif, format, LYD_PRINT_SHRINK, -1, &inner, NULL))) {
        goto cleanup;
    }

    if (format == LYD_XML) {
        r = asprintf(&str, "<notification xmlns=\"%s\"><eventTime>%s</eventTime>%s</notification>",
                SRUDPN_RFC5277_XML_NS, event_time_str, inner);
    } else {
        /* the members of the printed object follow eventTime in the envelope object */
        inner_end = strrchr(inner, '}');
        SR_CHECK_INT_GOTO((inner[0] != '{') || !inner_end, err_info, cleanup);
        r = asprintf(&str, "{\"%s:notification\":{\"eventTime\":\"%s\",%.*s}}", SRUDPN_RFC5277_JSON_MODULE,
                event_time_str, (int)(inner_end - inner - 1), inner + 1);
    }
    if (r == -1) {
        SR_ERRINFO_MEM(&err_info);
        goto cleanup;
    }
    *payload = (uint8_t *)str;
    *payload_len = r;

cleanup:
    free(event_time_str);
    free(inner);
    return sr_api_ret(NULL, err_info);
}

API int
srudpn_build_dgrams(srudpn_media_type_t media_type, uint32_t publisher_id, uint32_t message_id, const uint8_t *payload,
        uint32_t payload_len, uint16_t max_segment_size, srudpn_dgram_t **dgrams)
{
    sr_error_info_t *err_info = NULL;
    srudpn_dgram_t *dgram;
    LYA_COUNT_T i;
    uint32_t count, seg_size;
    uint16_t msg_len, seg_field;
    uint8_t hdr_len;

    SR_CHECK_ARG_APIRET((media_type < SRUDPN_MT_JSON) || (media_type > SRUDPN_MT_CBOR) || !payload || !payload_len ||
            !dgrams, NULL, err_info);

    *dgrams = NULL;

    if (!max_segment_size ||
            ((max_segment_size >= SRUDPN_HDR_SIZE) && (payload_len <= (uint32_t)(max_segment_size - SRUDPN_HDR_SIZE)))) {
        /* unsegmented */
        if (payload_len > SRUDPN_MAX_DGRAM_SIZE - SRUDPN_HDR_SIZE) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "UDP-Notif message payload of %" PRIu32 " octets does not fit "
                    "into a datagram.", payload_len);
            goto cleanup;
        }
        hdr_len = SRUDPN_HDR_SIZE;
        seg_size = payload_len;
        count = 1;
    } else {
        hdr_len = SRUDPN_HDR_SIZE + SRUDPN_OPT_SEGMENTATION_SIZE;
        if (max_segment_size <= hdr_len) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "UDP-Notif maximum segment size %" PRIu16 " does not fit "
                    "the header.", max_segment_size);
            goto cleanup;
        }
        seg_size = max_segment_size - hdr_len;
        count = payload_len / seg_size + (payload_len % seg_size ? 1 : 0);
        if (count > SRUDPN_MAX_SEGMENTS) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "UDP-Notif message payload of %" PRIu32 " octets needs more "
                    "than %d segments.", payload_len, SRUDPN_MAX_SEGMENTS);
            goto cleanup;
        }
    }

    LYA_NEW(*dgrams, count, SR_ERRINFO_MEM(&err_info); goto cleanup);

    LYA_FOR(*dgrams, i) {
        dgram = &(*dgrams)[i];
        dgram->hdr_len = hdr_len;
        dgram->data = payload + i * seg_size;
        dgram->data_len = (i < count - 1) ? seg_size : payload_len - i * seg_size;
        msg_len = hdr_len + dgram->data_len;

        /* Ver, S-flag unset, MT, Header Len, Message Length, Publisher ID, Message ID */
        dgram->hdr[0] = (SRUDPN_VERSION << 5) | media_type;
        dgram->hdr[1] = hdr_len;
        dgram->hdr[2] = msg_len >> 8;
        dgram->hdr[3] = msg_len & 0xFF;
        dgram->hdr[4] = publisher_id >> 24;
        dgram->hdr[5] = (publisher_id >> 16) & 0xFF;
        dgram->hdr[6] = (publisher_id >> 8) & 0xFF;
        dgram->hdr[7] = publisher_id & 0xFF;
        dgram->hdr[8] = message_id >> 24;
        dgram->hdr[9] = (message_id >> 16) & 0xFF;
        dgram->hdr[10] = (message_id >> 8) & 0xFF;
        dgram->hdr[11] = message_id & 0xFF;

        if (hdr_len > SRUDPN_HDR_SIZE) {
            /* segmentation option, Segment Number and L-flag */
            seg_field = (i << 1) | (i == count - 1);
            dgram->hdr[12] = SRUDPN_OPT_SEGMENTATION;
            dgram->hdr[13] = SRUDPN_OPT_SEGMENTATION_SIZE;
            dgram->hdr[14] = seg_field >> 8;
            dgram->hdr[15] = seg_field & 0xFF;
        }
    }

cleanup:
    if (err_info) {
        LYA_FREE(*dgrams);
        *dgrams = NULL;
    }
    return sr_api_ret(NULL, err_info);
}
