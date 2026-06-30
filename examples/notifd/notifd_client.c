/**
 * @file notifd_client.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief example UDP-Notif receiver client for sysrepo-notifd
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
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

/** UDP-Notif protocol version (draft-ietf-netconf-udp-notif-25) */
#define UDP_NOTIF_VERSION 1

/** Fixed header size in bytes (without options) */
#define UDP_NOTIF_HDR_SIZE 12

/** Segmentation option size in bytes */
#define UDP_NOTIF_SEG_OPT_SIZE 4

/** Segmentation option type */
#define UDP_NOTIF_OPT_SEGMENTATION 1

/** Maximum UDP datagram size */
#define UDP_MAX_SIZE 65535

/** Media type: application/yang-data+json */
#define UDP_NOTIF_MT_JSON 1

/** Media type: application/yang-data+xml */
#define UDP_NOTIF_MT_XML 2

/** Default receive timeout in milliseconds */
#define DEFAULT_RECV_TIMEOUT_MS 5000

/** Maximum pending messages for reassembly */
#define MAX_PENDING_MESSAGES 16

/** Maximum segments per message */
#define MAX_SEGMENTS_PER_MESSAGE 256

/** Reassembly timeout in seconds */
#define SEGMENT_REASSEMBLY_TIMEOUT 30

/** Media type name strings */
static const char *media_type_names[] = {
    "reserved",
    "application/yang-data+json",
    "application/yang-data+xml",
    "application/yang-data+cbor"
};

/** Global flag for clean shutdown on SIGINT */
static volatile sig_atomic_t exit_application;

/**
 * @brief Parsed UDP-Notif header fields.
 */
typedef struct {
    uint8_t version;            /**< protocol version */
    uint8_t s_flag;             /**< S-flag (media type space) */
    uint8_t media_type;         /**< media type identifier */
    uint8_t header_len;         /**< total header length including options */
    uint16_t message_len;       /**< message length */
    uint32_t publisher_id;      /**< message publisher ID */
    uint32_t message_id;        /**< message ID */
    int has_segmentation;       /**< whether segmentation option is present */
    uint16_t segment_num;       /**< segment number (0-based) */
    int is_last_segment;        /**< whether this is the last segment */
} udp_notif_header_t;

/**
 * @brief Segment buffer for message reassembly.
 */
typedef struct {
    uint8_t *data;              /**< segment payload data */
    size_t len;                 /**< segment payload length */
    int received;               /**< whether segment was received */
} segment_buffer_t;

/**
 * @brief Pending message being reassembled from segments.
 */
typedef struct {
    uint32_t publisher_id;          /**< publisher ID */
    uint32_t message_id;            /**< message ID */
    uint8_t media_type;             /**< media type from first segment */
    segment_buffer_t *segments;     /**< array of segment buffers */
    uint16_t total_segments;        /**< total segments (0 if unknown) */
    uint16_t received_count;        /**< number of received segments */
    struct timespec first_received; /**< timestamp of first segment */
    int active;                     /**< whether this slot is in use */
} pending_message_t;

/** Pending messages for reassembly */
static pending_message_t pending_messages[MAX_PENDING_MESSAGES];

/**
 * @brief Signal handler for clean shutdown.
 */
static void
sigint_handler(int signum)
{
    (void)signum;

    exit_application = 1;
}

/**
 * @brief Print usage help.
 */
static void
help_print(void)
{
    printf(
            "Usage: notifd_client <port> [options]\n"
            "\n"
            "Arguments:\n"
            "  port          UDP port to listen on\n"
            "\n"
            "Options:\n"
            "  -h            Show this help\n"
            "  -a <addr>     IP address to bind to (default 0.0.0.0)\n"
            "  -t <ms>       Receive timeout in ms (default 5000, 0 for infinite)\n"
            "\n");
}

/**
 * @brief Parse the UDP-Notif message header from raw data.
 *
 * @param[in] data Received UDP data.
 * @param[in] data_len Length of received data.
 * @param[out] hdr Parsed header structure.
 * @return 0 on success, -1 on error.
 */
static int
parse_udp_notif_header(const uint8_t *data, size_t data_len, udp_notif_header_t *hdr)
{
    size_t opt_offset;
    uint8_t opt_type, opt_len;
    uint16_t seg_field;

    if (data_len < UDP_NOTIF_HDR_SIZE) {
        return -1;
    }

    /* byte 0: version (bits 7-5), S-flag (bit 4), media type (bits 3-0) */
    hdr->version = (data[0] >> 5) & 0x07;
    hdr->s_flag = (data[0] >> 4) & 0x01;
    hdr->media_type = data[0] & 0x0F;

    /* byte 1: total header length in 32-bit words including options */
    hdr->header_len = data[1];

    /* bytes 2-3, 4-7, 8-11: multi-byte fields in network byte order */
    hdr->message_len = ((uint16_t)data[2] << 8) | data[3];
    hdr->publisher_id = ((uint32_t)data[4] << 24) | ((uint32_t)data[5] << 16) |
            ((uint32_t)data[6] << 8) | data[7];
    hdr->message_id = ((uint32_t)data[8] << 24) | ((uint32_t)data[9] << 16) |
            ((uint32_t)data[10] << 8) | data[11];

    hdr->has_segmentation = 0;

    /* parse TLV-encoded options following the fixed header */
    if (hdr->header_len > UDP_NOTIF_HDR_SIZE) {
        opt_offset = UDP_NOTIF_HDR_SIZE;
        while (opt_offset + 2 <= hdr->header_len) {
            opt_type = data[opt_offset];
            opt_len = data[opt_offset + 1];

            /* segmentation option: 2-byte field encoding segment number (bits 15-1)
               and last-segment flag (bit 0) */
            if ((opt_type == UDP_NOTIF_OPT_SEGMENTATION) && (opt_len == UDP_NOTIF_SEG_OPT_SIZE)) {
                hdr->has_segmentation = 1;
                seg_field = ((uint16_t)data[opt_offset + 2] << 8) | data[opt_offset + 3];
                hdr->segment_num = (seg_field >> 1) & 0x7FFF;
                hdr->is_last_segment = seg_field & 0x01;
            }

            /* advance past this option (opt_len includes type and length bytes) */
            opt_offset += opt_len;
        }
    }

    return 0;
}

/**
 * @brief Create a UDP socket bound to the given address and port.
 *
 * @param[in] port Port number to bind to.
 * @param[in] addr IP address to bind to (NULL for INADDR_ANY).
 * @return Socket FD on success, -1 on error.
 */
static int
create_udp_socket(uint16_t port, const char *addr)
{
    int sockfd;
    struct sockaddr_in sa;
    int opt = 1;

    /* create an IPv4 UDP socket */
    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        fprintf(stderr, "Failed to create socket: %s\n", strerror(errno));
        return -1;
    }

    /* allow quick rebinding after exit without waiting for TIME_WAIT to expire */
    if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt))) {
        fprintf(stderr, "Failed to set SO_REUSEADDR socket option: %s\n", strerror(errno));
        close(sockfd);
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(port);
    if (addr) {
        if (inet_pton(AF_INET, addr, &sa.sin_addr) != 1) {
            fprintf(stderr, "Invalid IP address: %s\n", addr);
            close(sockfd);
            return -1;
        }
    } else {
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
    }

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        fprintf(stderr, "Failed to bind socket to %s:%" PRIu16 ": %s\n",
                addr ? addr : "0.0.0.0", port, strerror(errno));
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * @brief Find or create a pending message slot for reassembly.
 *
 * @param[in] publisher_id Publisher ID.
 * @param[in] message_id Message ID.
 * @param[in] media_type Media type from the segment.
 * @return Pending message slot, or NULL on error.
 */
static pending_message_t *
find_or_create_pending(uint32_t publisher_id, uint32_t message_id, uint8_t media_type)
{
    pending_message_t *oldest = NULL;
    struct timespec oldest_time = {0};
    struct timespec now;
    int i, j;

    clock_gettime(CLOCK_REALTIME, &now);

    /* look for an existing pending message matching the publisher+message ID */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        if (pending_messages[i].active &&
                (pending_messages[i].publisher_id == publisher_id) &&
                (pending_messages[i].message_id == message_id)) {
            return &pending_messages[i];
        }

        /* track the oldest active message as eviction candidate */
        if (pending_messages[i].active) {
            if (!oldest ||
                    ((pending_messages[i].first_received.tv_sec < oldest_time.tv_sec) ||
                    ((pending_messages[i].first_received.tv_sec == oldest_time.tv_sec) &&
                    (pending_messages[i].first_received.tv_nsec < oldest_time.tv_nsec)))) {
                oldest = &pending_messages[i];
                oldest_time = pending_messages[i].first_received;
            }
        }
    }

    /* try to find a free slot */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        if (!pending_messages[i].active) {
            pending_messages[i].active = 1;
            pending_messages[i].publisher_id = publisher_id;
            pending_messages[i].message_id = message_id;
            pending_messages[i].media_type = media_type;
            pending_messages[i].segments = calloc(MAX_SEGMENTS_PER_MESSAGE, sizeof(segment_buffer_t));
            pending_messages[i].total_segments = 0;
            pending_messages[i].received_count = 0;
            pending_messages[i].first_received = now;
            return &pending_messages[i];
        }
    }

    /* no free slots, evict the oldest message if it has timed out */
    if (oldest && ((now.tv_sec - oldest->first_received.tv_sec) > SEGMENT_REASSEMBLY_TIMEOUT)) {
        for (j = 0; j < MAX_SEGMENTS_PER_MESSAGE; j++) {
            free(oldest->segments[j].data);
        }
        free(oldest->segments);

        oldest->active = 1;
        oldest->publisher_id = publisher_id;
        oldest->message_id = message_id;
        oldest->media_type = media_type;
        oldest->segments = calloc(MAX_SEGMENTS_PER_MESSAGE, sizeof(segment_buffer_t));
        oldest->total_segments = 0;
        oldest->received_count = 0;
        oldest->first_received = now;
        return oldest;
    }

    return NULL;
}

/**
 * @brief Free a pending message slot.
 *
 * @param[in] pending Pending message to free.
 */
static void
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
 * @brief Add a segment to a pending message and check for completion.
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
        return NULL;
    }

    /* store the segment payload unless this is a duplicate */
    if (!pending->segments[segment_num].received) {
        pending->segments[segment_num].data = malloc(payload_len);
        if (!pending->segments[segment_num].data) {
            return NULL;
        }
        memcpy(pending->segments[segment_num].data, payload, payload_len);
        pending->segments[segment_num].len = payload_len;
        pending->segments[segment_num].received = 1;
        pending->received_count++;
    }

    /* the last segment tells us the total segment count */
    if (is_last) {
        pending->total_segments = segment_num + 1;
    }

    /* reassemble once every expected segment has been received */
    if ((pending->total_segments > 0) && (pending->received_count == pending->total_segments)) {
        *total_len = 0;
        for (i = 0; i < pending->total_segments; i++) {
            if (!pending->segments[i].received) {
                return NULL;
            }
            *total_len += pending->segments[i].len;
        }

        reassembled = malloc(*total_len + 1);
        if (!reassembled) {
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

/**
 * @brief Print a notification data tree in a human-readable format.
 *
 * @param[in] notif Notification data tree.
 * @param[in] hdr UDP-Notif header that carried the notification.
 */
static void
print_notification(const struct lyd_node *notif, const udp_notif_header_t *hdr)
{
    char *path = NULL;
    char *payload = NULL;
    const char *mt_name;

    path = lyd_path(notif, LYD_PATH_STD, NULL, 0);
    if (!path) {
        path = strdup("(unknown-path)");
    }

    mt_name = (hdr->media_type < 4) ? media_type_names[hdr->media_type] : "unknown";

    printf("\n--- Notification ---\n");
    printf("  Path:          %s\n", path);
    printf("  Publisher ID:  %" PRIu32 "\n", hdr->publisher_id);
    printf("  Message ID:    %" PRIu32 "\n", hdr->message_id);
    printf("  Media Type:    %s\n", mt_name);

    if (!lyd_print_mem(&payload, notif, LYD_JSON, 0)) {
        printf("  Payload:\n%s\n", payload);
    }

    printf("---------------------\n");
    fflush(stdout);

    free(path);
    free(payload);
}

/**
 * @brief Receive and process one UDP-Notif message (or segment).
 *
 * Handles both unsegmented and segmented messages. For segmented messages,
 * collects all segments and reassembles before parsing. Loops internally
 * to collect remaining segments when needed.
 *
 * @param[in] sockfd UDP socket FD.
 * @param[in] conn sysrepo connection for acquiring the libyang context.
 * @param[in] timeout_ms Timeout in milliseconds per receive attempt.
 * @return 0 on success (notification received and printed), 1 on timeout, -1 on error.
 */
static int
receive_notification(int sockfd, sr_conn_ctx_t *conn, int timeout_ms)
{
    uint8_t buffer[UDP_MAX_SIZE];
    ssize_t recv_len;
    udp_notif_header_t hdr;
    const uint8_t *payload;
    size_t payload_len, reassembled_len;
    struct ly_in *in = NULL;
    struct lyd_node *notif = NULL;
    const struct ly_ctx *ly_ctx = NULL;
    LYD_FORMAT format;
    pending_message_t *pending;
    char *reassembled = NULL;
    char *payload_str = NULL;
    struct pollfd pfd;
    int r, rc = 0;

receive_next:
    if (exit_application) {
        rc = -1;
        goto cleanup;
    }

    pfd.fd = sockfd;
    pfd.events = POLLIN;

    /* wait up to timeout_ms for an incoming datagram */
    r = poll(&pfd, 1, timeout_ms);
    if (r < 0) {
        if (errno == EINTR) {
            if (exit_application) {
                rc = -1;
                goto cleanup;
            }
            return 1;
        }
        fprintf(stderr, "poll() failed: %s\n", strerror(errno));
        rc = -1;
        goto cleanup;
    }
    if (r == 0) {
        return 1;
    }

    recv_len = recv(sockfd, buffer, sizeof(buffer), 0);
    if (recv_len < 0) {
        fprintf(stderr, "recv() failed: %s\n", strerror(errno));
        rc = -1;
        goto cleanup;
    }

    /* parse the UDP-Notif header from the received data */
    if (parse_udp_notif_header(buffer, recv_len, &hdr)) {
        fprintf(stderr, "Failed to parse UDP-Notif header\n");
        rc = -1;
        goto cleanup;
    }

    if (hdr.version != UDP_NOTIF_VERSION) {
        fprintf(stderr, "Unsupported UDP-Notif version: %" PRIu8 "\n", hdr.version);
        rc = -1;
        goto cleanup;
    }

    /* payload starts right after the header (including any options) */
    payload = buffer + hdr.header_len;
    payload_len = recv_len - hdr.header_len;

    /* segmented messages require reassembly before they can be parsed */
    if (hdr.has_segmentation) {
        pending = find_or_create_pending(hdr.publisher_id, hdr.message_id, hdr.media_type);
        if (!pending) {
            fprintf(stderr, "Failed to create pending message for reassembly\n");
            rc = -1;
            goto cleanup;
        }

        reassembled = add_segment(pending, hdr.segment_num, hdr.is_last_segment,
                payload, payload_len, &reassembled_len);

        /* not all segments received yet -- go back and wait for more */
        if (!reassembled) {
            goto receive_next;
        }

        /* reassembly complete: use the combined payload */
        payload_str = reassembled;
        payload_len = reassembled_len;

        /* use the media type stored when the first segment arrived */
        hdr.media_type = pending->media_type;
        free_pending_message(pending);
    } else {
        if (payload_len == 0) {
            fprintf(stderr, "Empty payload in unsegmented message\n");
            rc = -1;
            goto cleanup;
        }

        payload_str = malloc(payload_len + 1);
        if (!payload_str) {
            fprintf(stderr, "Memory allocation failed\n");
            rc = -1;
            goto cleanup;
        }
        memcpy(payload_str, payload, payload_len);
        payload_str[payload_len] = '\0';
    }

    switch (hdr.media_type) {
    case UDP_NOTIF_MT_JSON:
        format = LYD_JSON;
        break;
    case UDP_NOTIF_MT_XML:
        format = LYD_XML;
        break;
    default:
        fprintf(stderr, "Unsupported media type: %" PRIu8 "\n", hdr.media_type);
        rc = -1;
        goto cleanup;
    }

    /* acquire libyang context only for the duration of parsing and printing */
    ly_ctx = sr_acquire_context(conn);
    if (!ly_ctx) {
        fprintf(stderr, "Failed to acquire libyang context\n");
        rc = -1;
        goto cleanup;
    }

    if (ly_in_new_memory(payload_str, &in)) {
        fprintf(stderr, "Failed to create libyang input\n");
        rc = -1;
        goto cleanup;
    }

    if (lyd_parse_op(ly_ctx, NULL, in, format, LYD_TYPE_NOTIF_YANG, 0, NULL, &notif)) {
        fprintf(stderr, "Failed to parse notification: %s\n", ly_err_last(ly_ctx)->msg);
        rc = -1;
        goto cleanup;
    }

    print_notification(notif, &hdr);

    /* release context right after we're done using it */
    sr_release_context(conn);
    ly_ctx = NULL;

cleanup:
    free(payload_str);
    lyd_free_all(notif);
    ly_in_free(in, 0);
    if (ly_ctx) {
        sr_release_context(conn);
    }
    return rc;
}

int
main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    int sockfd = -1;
    uint16_t port = 0;
    const char *addr = NULL;
    int timeout_ms = DEFAULT_RECV_TIMEOUT_MS;
    int opt, rc = EXIT_SUCCESS, r, i;

    while ((opt = getopt(argc, argv, "a:ht:")) != -1) {
        switch (opt) {
        case 'a':
            addr = optarg;
            break;
        case 'h':
            help_print();
            return EXIT_SUCCESS;
        case 't':
            timeout_ms = atoi(optarg);
            break;
        default:
            help_print();
            return EXIT_FAILURE;
        }
    }

    if (optind >= argc) {
        fprintf(stderr, "Missing required port argument.\n\n");
        help_print();
        return EXIT_FAILURE;
    }

    port = (uint16_t)strtoul(argv[optind], NULL, 10);
    if (port == 0) {
        fprintf(stderr, "Invalid port number: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    /* install signal handlers for clean shutdown */
    signal(SIGINT, sigint_handler);

    /* ignore SIGPIPE -- prevents crash if a send fails on a disconnected peer */
    signal(SIGPIPE, SIG_IGN);

    /* connect to sysrepo -- the libyang context is acquired per-notification
       in receive_notification() so it is not held while waiting for data */
    printf("Connecting to sysrepo...\n");

    r = sr_connect(0, &conn);
    if (r != SR_ERR_OK) {
        fprintf(stderr, "Failed to connect to sysrepo: %s\n", sr_strerror(r));
        return EXIT_FAILURE;
    }

    printf("Creating UDP socket on %s:%" PRIu16 "...\n", addr ? addr : "0.0.0.0", port);

    sockfd = create_udp_socket(port, addr);
    if (sockfd < 0) {
        rc = EXIT_FAILURE;
        goto cleanup;
    }

    printf("Listening for UDP-Notif messages (timeout %d ms)...\n", timeout_ms);
    printf("Press Ctrl+C to stop.\n\n");

    /* main receive loop: one notification per successful call,
       timeouts (r == 1) are silently retried */
    while (!exit_application) {
        r = receive_notification(sockfd, conn, timeout_ms);
        if (r < 0) {
            if (exit_application) {
                break;
            }
            rc = EXIT_FAILURE;
            break;
        }
    }

    printf("\nShutting down...\n");

cleanup:
    if (sockfd >= 0) {
        close(sockfd);
    }

    /* clean up any partially reassembled messages */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        free_pending_message(&pending_messages[i]);
    }

    sr_disconnect(conn);
    return rc;
}
