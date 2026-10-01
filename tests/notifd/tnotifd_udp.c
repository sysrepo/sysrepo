/**
 * @file tnotifd_udp.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief UDP-Notif receiver of the sysrepo-notifd tests
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
#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "tests/tcommon.h"
#include "tnotifd.h"

/** Maximum number of segments per message */
#define MAX_SEGMENTS_PER_MESSAGE 256

/**
 * @brief Parse UDP-Notif header from received data.
 *
 * @param[in] data Received UDP data.
 * @param[in] data_len Length of received data.
 * @param[out] header Parsed header structure.
 * @return 0 on success, -1 on error.
 */
static int
parse_udp_notif_header(const uint8_t *data, size_t data_len, udp_notif_header_t *header)
{
    if (data_len < UDP_NOTIF_HDR_SIZE) {
        return -1;
    }

    header->version = (data[0] >> 5) & 0x07;
    header->s_flag = (data[0] >> 4) & 0x01;
    header->media_type = data[0] & 0x0F;
    header->header_len = data[1];
    header->message_len = ((uint16_t)data[2] << 8) | data[3];
    header->publisher_id = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
            ((uint32_t)data[6] << 8) | data[7];
    header->message_id = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
            ((uint32_t)data[10] << 8) | data[11];

    header->has_segmentation = 0;
    if (header->header_len > UDP_NOTIF_HDR_SIZE) {
        size_t opt_offset = UDP_NOTIF_HDR_SIZE;

        while (opt_offset + 2 <= header->header_len) {
            uint8_t opt_type = data[opt_offset];
            uint8_t opt_len = data[opt_offset + 1];

            if ((opt_type == 1) && (opt_len == UDP_NOTIF_SEG_OPT_SIZE)) {
                header->has_segmentation = 1;
                uint16_t seg_field = ((uint16_t)data[opt_offset + 2] << 8) | data[opt_offset + 3];

                header->segment_num = (seg_field >> 1) & 0x7FFF;
                header->is_last_segment = seg_field & 0x01;
            }
            opt_offset += opt_len;
        }
    }

    return 0;
}

/**
 * @brief Set a monotonic deadline @p timeout_ms milliseconds from now.
 *
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[out] deadline Resulting deadline.
 */
static void
deadline_set(uint32_t timeout_ms, struct timespec *deadline)
{
    clock_gettime(CLOCK_MONOTONIC, deadline);
    deadline->tv_sec += timeout_ms / 1000;
    deadline->tv_nsec += (long)(timeout_ms % 1000) * 1000000;
    if (deadline->tv_nsec >= 1000000000) {
        deadline->tv_nsec -= 1000000000;
        ++deadline->tv_sec;
    }
}

/**
 * @brief Get the time remaining until a deadline.
 *
 * @param[in] deadline Deadline to check.
 * @return Milliseconds remaining, 0 if the deadline has passed.
 */
static int
deadline_remaining(const struct timespec *deadline)
{
    struct timespec now;
    int64_t ms;

    clock_gettime(CLOCK_MONOTONIC, &now);
    ms = ((int64_t)deadline->tv_sec - now.tv_sec) * 1000;
    ms += ((int64_t)deadline->tv_nsec - now.tv_nsec) / 1000000;

    return (ms > 0) ? (int)ms : 0;
}

/**
 * @brief Poll a socket for available data until a deadline.
 *
 * @param[in] sockfd Socket FD to poll.
 * @param[in] deadline Deadline to poll until.
 * @return 1 if data available, 0 on timeout, -1 on error.
 */
static int
poll_for_data(int sockfd, const struct timespec *deadline)
{
    struct pollfd pfd;
    int r;

    pfd.fd = sockfd;
    pfd.events = POLLIN;

    do {
        r = poll(&pfd, 1, deadline_remaining(deadline));
    } while ((r < 0) && (errno == EINTR));

    return r;
}

/**
 * @brief Find or create a pending message slot for reassembly.
 *
 * @param[in] reasm Reassembly context.
 * @param[in] publisher_id Publisher ID.
 * @param[in] message_id Message ID.
 * @param[in] media_type Media type.
 * @return Pending message slot, NULL if none is free.
 */
static pending_message_t *
find_or_create_pending(struct notif_reasm *reasm, uint32_t publisher_id, uint32_t message_id,
        uint8_t media_type)
{
    pending_message_t *pending;
    int i;

    /* first, look for an existing entry */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        pending = &reasm->msgs[i];
        if (pending->active && (pending->publisher_id == publisher_id) && (pending->message_id == message_id)) {
            return pending;
        }
    }

    /* then for a free slot */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        pending = &reasm->msgs[i];
        if (pending->active) {
            continue;
        }

        pending->segments = calloc(MAX_SEGMENTS_PER_MESSAGE, sizeof *pending->segments);
        if (!pending->segments) {
            return NULL;
        }
        pending->publisher_id = publisher_id;
        pending->message_id = message_id;
        pending->media_type = media_type;
        pending->total_segments = 0;
        pending->received_count = 0;
        pending->active = 1;
        return pending;
    }

    TLOG_ERR("No free reassembly slot for message %" PRIu32, message_id);
    return NULL;
}

void
free_pending_message(pending_message_t *pending)
{
    int i;

    if (!pending || !pending->active) {
        return;
    }

    for (i = 0; i < MAX_SEGMENTS_PER_MESSAGE; i++) {
        free(pending->segments[i].data);
        pending->segments[i].data = NULL;
        pending->segments[i].len = 0;
        pending->segments[i].received = 0;
    }
    free(pending->segments);
    pending->segments = NULL;
    pending->active = 0;
}

/**
 * @brief Add a segment to pending message.
 *
 * @param[in] pending Pending message.
 * @param[in] segment_num Segment number.
 * @param[in] is_last Whether this is the last segment.
 * @param[in] payload Segment payload data.
 * @param[in] payload_len Segment payload length.
 * @param[out] total_len Total reassembled length (if complete).
 * @return Reassembled payload if complete, NULL otherwise (caller must free).
 */
static char *
add_segment(pending_message_t *pending, uint16_t segment_num, int is_last,
        const uint8_t *payload, size_t payload_len, size_t *total_len)
{
    char *reassembled = NULL;
    uint16_t i;
    size_t offset;

    if (segment_num >= MAX_SEGMENTS_PER_MESSAGE) {
        TLOG_ERR("Segment number %d exceeds maximum", segment_num);
        return NULL;
    }

    /* store segment */
    if (!pending->segments[segment_num].received) {
        pending->segments[segment_num].data = malloc(payload_len);
        if (!pending->segments[segment_num].data) {
            TLOG_ERR("Memory allocation failed");
            return NULL;
        }
        memcpy(pending->segments[segment_num].data, payload, payload_len);
        pending->segments[segment_num].len = payload_len;
        pending->segments[segment_num].received = 1;
        pending->received_count++;
    }

    /* update total segments count if this is the last segment */
    if (is_last) {
        pending->total_segments = segment_num + 1;
    }

    /* check if all segments received */
    if ((pending->total_segments > 0) && (pending->received_count == pending->total_segments)) {
        /* reassemble */
        *total_len = 0;
        for (i = 0; i < pending->total_segments; i++) {
            if (!pending->segments[i].received) {
                TLOG_ERR("Missing segment %d during reassembly", i);
                return NULL;
            }
            *total_len += pending->segments[i].len;
        }

        reassembled = malloc(*total_len + 1);
        if (!reassembled) {
            TLOG_ERR("Memory allocation failed for reassembly");
            return NULL;
        }

        offset = 0;
        for (i = 0; i < pending->total_segments; i++) {
            memcpy(reassembled + offset, pending->segments[i].data, pending->segments[i].len);
            offset += pending->segments[i].len;
        }
        reassembled[*total_len] = '\0';

        return reassembled;
    }

    return NULL;
}

int
create_udp_receiver_socket(uint16_t *port)
{
    int sockfd, rcvbuf = 4 * 1024 * 1024;
    struct sockaddr_in addr;
    socklen_t addr_len;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    /* a burst of segments overflows the default buffer, the kernel clamps the size to its maximum */
    setsockopt(sockfd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof rcvbuf);

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    /* no SO_REUSEADDR, parallel tests could bind the same port and steal each other's notifications */
    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }

    /* learn the assigned port */
    addr_len = sizeof(addr);
    if (getsockname(sockfd, (struct sockaddr *)&addr, &addr_len) < 0) {
        close(sockfd);
        return -1;
    }
    *port = ntohs(addr.sin_port);

    return sockfd;
}

/**
 * @brief Receive and parse a notification from UDP socket, waiting until a deadline.
 *
 * @param[in] st Test state.
 * @param[in] sockfd UDP socket FD.
 * @param[in] deadline Deadline to wait until.
 * @param[out] notif Parsed notification (caller must free), NULL on timeout.
 * @param[out] header Optional parsed header (can be NULL).
 * @param[out] src_addr Optional buffer for the source address (can be NULL).
 * @param[in] src_addr_len Size of @p src_addr.
 * @return ::NOTIF_RECV_OK, ::NOTIF_RECV_TIMEOUT or ::NOTIF_RECV_ERR.
 */
static int
receive_notif_deadline(struct tnotifd_state *st, int sockfd, const struct timespec *deadline,
        struct lyd_node **notif, udp_notif_header_t *header, char *src_addr, size_t src_addr_len)
{
    uint8_t buffer[UDP_MAX_SIZE];
    ssize_t recv_len;
    udp_notif_header_t hdr;
    const uint8_t *payload;
    size_t payload_len, reassembled_len;
    struct ly_in *in = NULL;
    LYD_FORMAT format;
    enum lyd_type dt;
    struct lyd_node *envp = NULL;
    pending_message_t *pending;
    char *reassembled = NULL;
    char *payload_str = NULL;
    struct sockaddr_storage src_sockaddr;
    socklen_t src_sockaddr_len;
    const void *src_ptr;
    int family;
    int r;
    int rc = NOTIF_RECV_ERR;

    *notif = NULL;
    if (src_addr && src_addr_len) {
        src_addr[0] = '\0';
    }

receive_next:
    memset(&src_sockaddr, 0, sizeof(src_sockaddr));
    src_sockaddr_len = sizeof(src_sockaddr);

    /* poll for data until the shared deadline */
    r = poll_for_data(sockfd, deadline);
    if (r < 0) {
        TLOG_ERR("poll() failed: %s", strerror(errno));
        return NOTIF_RECV_ERR;
    }
    if (r == 0) {
        return NOTIF_RECV_TIMEOUT;
    }

    recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_sockaddr, &src_sockaddr_len);
    if (recv_len < 0) {
        TLOG_ERR("recvfrom() failed: %s", strerror(errno));
        return NOTIF_RECV_ERR;
    }

    if (src_addr && src_addr_len) {
        src_ptr = NULL;
        family = ((struct sockaddr *)&src_sockaddr)->sa_family;
        if (family == AF_INET) {
            src_ptr = &((struct sockaddr_in *)&src_sockaddr)->sin_addr;
        } else if (family == AF_INET6) {
            src_ptr = &((struct sockaddr_in6 *)&src_sockaddr)->sin6_addr;
        }

        if (src_ptr && !inet_ntop(family, src_ptr, src_addr, src_addr_len)) {
            src_addr[0] = '\0';
        }
    }

    if (parse_udp_notif_header(buffer, recv_len, &hdr)) {
        TLOG_ERR("Failed to parse UDP-Notif header");
        return NOTIF_RECV_ERR;
    }

    if (hdr.version != UDP_NOTIF_VERSION) {
        TLOG_ERR("Invalid UDP-Notif version: %d", hdr.version);
        return NOTIF_RECV_ERR;
    }

    payload = buffer + hdr.header_len;
    payload_len = recv_len - hdr.header_len;

    /* handle segmentation */
    if (hdr.has_segmentation) {
        TLOG_INF("Received segment %d%s for message %u",
                hdr.segment_num, hdr.is_last_segment ? " (last)" : "", hdr.message_id);

        pending = find_or_create_pending(&st->reasm, hdr.publisher_id, hdr.message_id, hdr.media_type);
        if (!pending) {
            TLOG_ERR("Failed to create pending message for reassembly");
            return NOTIF_RECV_ERR;
        }

        reassembled = add_segment(pending, hdr.segment_num, hdr.is_last_segment,
                payload, payload_len, &reassembled_len);

        if (!reassembled) {
            /* not complete yet, wait for more segments */
            goto receive_next;
        }

        TLOG_INF("Message reassembly complete: %zu bytes from %d segments",
                reassembled_len, pending->total_segments);

        /* use reassembled payload */
        payload_str = reassembled;
        payload_len = reassembled_len;

        /* update header with info from the pending message */
        hdr.media_type = pending->media_type;
        hdr.seg_count = pending->total_segments;

        /* free the pending message slot */
        free_pending_message(pending);
    } else {
        hdr.seg_count = 1;

        /* non-segmented message, copy payload to null-terminated string */
        if (payload_len == 0) {
            TLOG_ERR("Empty payload");
            return NOTIF_RECV_ERR;
        }

        payload_str = malloc(payload_len + 1);
        if (!payload_str) {
            TLOG_ERR("Memory allocation failed");
            return NOTIF_RECV_ERR;
        }
        memcpy(payload_str, payload, payload_len);
        payload_str[payload_len] = '\0';
    }

    if (header) {
        *header = hdr;
    }

    switch (hdr.media_type) {
    case UDP_NOTIF_MT_JSON:
        format = LYD_JSON;
        break;
    case UDP_NOTIF_MT_XML:
        format = LYD_XML;
        break;
    default:
        TLOG_ERR("Unsupported media type: %d", hdr.media_type);
        goto cleanup;
    }

    if (ly_in_new_memory(payload_str, &in)) {
        TLOG_ERR("Failed to create libyang input");
        goto cleanup;
    }

    /* parse the RFC 5277 notification envelope; choose the parse type by encoding */
    dt = (format == LYD_XML) ? LYD_TYPE_NOTIF_NETCONF : LYD_TYPE_NOTIF_RESTCONF;
    if (lyd_parse_op(st->ly_ctx, NULL, in, format, dt, 0, &envp, notif)) {
        TLOG_ERR("Failed to parse notification: %s", ly_err_last(st->ly_ctx)->msg);
        goto cleanup;
    }

    /* *notif is the inner notification, the envelope is freed here */
    rc = NOTIF_RECV_OK;

cleanup:
    ly_in_free(in, 0);
    lyd_free_all(envp);
    free(payload_str);
    return rc;
}

int
recv_notif(struct tnotifd_state *st, int sockfd, const char *path, uint32_t timeout_ms,
        struct lyd_node **notif, udp_notif_header_t *header, char *src_addr, size_t src_addr_len)
{
    struct lyd_node *received = NULL;
    struct timespec deadline;
    char *received_path;
    int r;

    *notif = NULL;
    deadline_set(timeout_ms, &deadline);

    while (1) {
        r = receive_notif_deadline(st, sockfd, &deadline, &received, header, src_addr, src_addr_len);
        if (r != NOTIF_RECV_OK) {
            return r;
        }

        if (!path) {
            *notif = received;
            return NOTIF_RECV_OK;
        }

        received_path = lyd_path(received, LYD_PATH_STD, NULL, 0);
        r = received_path ? strcmp(received_path, path) : 1;
        free(received_path);
        if (!r) {
            *notif = received;
            return NOTIF_RECV_OK;
        }

        /* not the notification we are waiting for, discard it and keep waiting */
        lyd_free_all(received);
        received = NULL;
    }
}

/**
 * @brief Assert a notification with @p path arrives on @p sockfd, outputting its header.
 *
 * @param[in] st Test state.
 * @param[in] sockfd Socket to receive on.
 * @param[in] path Path of the notification to wait for.
 * @param[out] header Optional parsed UDP-Notif header (can be NULL).
 * @param[out] src_addr Optional buffer for the source address (can be NULL).
 * @param[in] src_addr_len Size of @p src_addr.
 * @return The notification, caller must free.
 */
static struct lyd_node *
expect_notif_full(struct tnotifd_state *st, int sockfd, const char *path, udp_notif_header_t *header,
        char *src_addr, size_t src_addr_len)
{
    struct lyd_node *notif = NULL;
    int r;

    TLOG_INF("Waiting for \"%s\"", path);

    r = recv_notif(st, sockfd, path, NOTIF_TIMEOUT_MS, &notif, header, src_addr, src_addr_len);
    if (r != NOTIF_RECV_OK) {
        TLOG_ERR("Did not receive \"%s\" (%s)", path, (r == NOTIF_RECV_TIMEOUT) ? "timeout" : "error");
    }
    assert_int_equal(r, NOTIF_RECV_OK);
    assert_non_null(notif);

    return notif;
}

struct lyd_node *
expect_notif(struct tnotifd_state *st, const char *path)
{
    return expect_notif_full(st, st->udp_sockfd, path, NULL, NULL, 0);
}

struct lyd_node *
expect_notif_hdr(struct tnotifd_state *st, const char *path, udp_notif_header_t *header)
{
    return expect_notif_full(st, st->udp_sockfd, path, header, NULL, 0);
}

struct lyd_node *
expect_notif_on(struct tnotifd_state *st, int sockfd, const char *path)
{
    return expect_notif_full(st, sockfd, path, NULL, NULL, 0);
}

struct lyd_node *
expect_notif_src(struct tnotifd_state *st, const char *path, char *src_addr, size_t src_addr_len)
{
    return expect_notif_full(st, st->udp_sockfd, path, NULL, src_addr, src_addr_len);
}

void
skip_notif(struct tnotifd_state *st, const char *path)
{
    lyd_free_all(expect_notif(st, path));
}

void
expect_notifs(struct tnotifd_state *st, const char **paths)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    uint8_t seen[8] = {0};
    uint32_t i, count, found = 0;

    for (count = 0; paths[count]; ++count) {}
    assert_true(count <= sizeof seen);

    while (found < count) {
        if (recv_notif(st, st->udp_sockfd, NULL, NOTIF_TIMEOUT_MS, &notif, NULL, NULL, 0) != NOTIF_RECV_OK) {
            TLOG_ERR("Received only %" PRIu32 " of %" PRIu32 " expected notifications", found, count);
            fail();
        }

        notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
        for (i = 0; i < count; ++i) {
            if (!seen[i] && notif_path && !strcmp(paths[i], notif_path)) {
                seen[i] = 1;
                ++found;
                break;
            }
        }
        free(notif_path);
        lyd_free_all(notif);
        notif = NULL;
    }
}

void
expect_no_notif(struct tnotifd_state *st, const char *path)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    int r;

    r = recv_notif(st, st->udp_sockfd, path, scale_timeout(st, QUIET_TIMEOUT_MS), &notif, NULL, NULL, 0);
    assert_int_not_equal(r, NOTIF_RECV_ERR);

    if (r == NOTIF_RECV_OK) {
        notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
        TLOG_ERR("Received unexpected notification \"%s\"", notif_path);
        free(notif_path);
        lyd_free_all(notif);
        fail();
    }
}

uint32_t
count_notifs(struct tnotifd_state *st, const char *path)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    uint32_t count = 0, timeout_ms = NOTIF_TIMEOUT_MS;

    while (recv_notif(st, st->udp_sockfd, NULL, timeout_ms, &notif, NULL, NULL, 0) == NOTIF_RECV_OK) {
        /* the first notification may take a while, any further one is already waiting */
        timeout_ms = scale_timeout(st, QUIET_TIMEOUT_MS);

        notif_path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
        if (notif_path && !strcmp(notif_path, path)) {
            ++count;
        }
        free(notif_path);
        lyd_free_all(notif);
        notif = NULL;
    }

    return count;
}

void
drain_notifs(struct tnotifd_state *st)
{
    uint8_t buffer[UDP_MAX_SIZE];
    struct timespec deadline;
    ssize_t recv_len;
    int count = 0;

    while (1) {
        deadline_set(scale_timeout(st, QUIET_TIMEOUT_MS), &deadline);
        if (poll_for_data(st->udp_sockfd, &deadline) <= 0) {
            break;
        }

        recv_len = recv(st->udp_sockfd, buffer, sizeof(buffer), 0);
        if (recv_len <= 0) {
            break;
        }
        ++count;
    }

    if (count) {
        TLOG_INF("Drained %d pending notification(s)", count);
    }
}

static int
can_bind_local_ipv4(const char *address)
{
    int sockfd;
    struct sockaddr_in addr;
    int rc;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return 0;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    if (inet_pton(AF_INET, address, &addr.sin_addr) != 1) {
        close(sockfd);
        return 0;
    }

    rc = bind(sockfd, (struct sockaddr *)&addr, sizeof(addr));
    close(sockfd);
    if (rc) {
        return 0;
    }

    return 1;
}

int
find_alternate_loopback_ipv4(const char *current_address, char *alternate_address, size_t alternate_address_len)
{
    int i;
    char candidate[INET_ADDRSTRLEN];

    if (!alternate_address || (alternate_address_len < INET_ADDRSTRLEN)) {
        return 0;
    }

    for (i = 2; i <= 254; i++) {
        snprintf(candidate, sizeof(candidate), "127.0.0.%d", i);
        if (current_address && !strcmp(candidate, current_address)) {
            continue;
        }
        if (can_bind_local_ipv4(candidate)) {
            strcpy(alternate_address, candidate);
            return 1;
        }
    }

    return 0;
}

int
renew_socket(struct tnotifd_state *st)
{
    int sockfd, i;
    uint16_t port;

    /* bound before the old one is closed, it could get the same port and its leftovers otherwise */
    sockfd = create_udp_receiver_socket(&port);
    if (sockfd < 0) {
        TLOG_ERR("Failed to create UDP socket");
        return 1;
    }

    close(st->udp_sockfd);
    st->udp_sockfd = sockfd;
    st->udp_port = port;

    /* the segments of a partially received message belong to the closed socket */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        free_pending_message(&st->reasm.msgs[i]);
    }

    return 0;
}
