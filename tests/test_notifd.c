/**
 * @file test_notifd.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief tests for sysrepo-notifd daemon and UDP notification transport
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
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <cmocka.h>
#include <libyang/libyang.h>

#include "common.h"
#include "sysrepo.h"
#include "tests/tcommon.h"

/** Path to sysrepo-notifd executable */
#define NOTIFD_PATH SR_BINARY_DIR "/sysrepo-notifd"

/** Path to sysrepoctl executable */
#define SYSREPOCTL_PATH SR_BINARY_DIR "/sysrepoctl"

/** Directory containing YANG modules */
#define SCHEMA_DIR TESTS_SRC_DIR "/../modules"

/** Directory containing subscribed_notifications YANG modules */
#define SN_YANG_DIR TESTS_SRC_DIR "/../modules/subscribed_notifications"

/** UDP port for testing */
#define TEST_UDP_PORT 47950

/** UDP-Notif protocol constants */
#define UDP_NOTIF_VERSION 1
#define UDP_NOTIF_HDR_SIZE 12
#define UDP_NOTIF_SEG_OPT_SIZE 4
#define UDP_MAX_SIZE 65535

/** UDP-Notif media types */
#define UDP_NOTIF_MT_JSON 1
#define UDP_NOTIF_MT_XML 2

/** Maximum time to wait for notification (milliseconds) */
#define NOTIF_TIMEOUT_MS 3000

/** Maximum number of segments to track for reassembly */
#define MAX_PENDING_MESSAGES 16

/** Maximum number of segments per message */
#define MAX_SEGMENTS_PER_MESSAGE 256

/** Timeout for segment reassembly in seconds */
#define SEGMENT_REASSEMBLY_TIMEOUT 30

/** Short timeout for draining notifications (milliseconds) */
#define DRAIN_TIMEOUT_MS 200

/** Long timeout for operations that may take a while (milliseconds) */
#define LONG_TIMEOUT_MS 10000

/** Poll interval for operational counter polling (milliseconds) */
#define COUNTER_POLL_MS 50

/** Total timeout for operational counter polling (milliseconds) */
#define COUNTER_WAIT_MS 5000

/**
 * @brief Segment buffer for message reassembly.
 */
typedef struct {
    uint8_t *data;              /**< segment payload data */
    size_t len;                 /**< segment payload length */
    int received;               /**< whether segment was received */
} segment_buffer_t;

/**
 * @brief Pending message for reassembly.
 */
typedef struct {
    uint32_t publisher_id;      /**< publisher ID */
    uint32_t message_id;        /**< message ID */
    uint8_t media_type;         /**< media type from first segment */
    segment_buffer_t *segments; /**< array of segment buffers */
    uint16_t total_segments;    /**< total number of segments (0 if unknown) */
    uint16_t received_count;    /**< number of received segments */
    time_t first_received;      /**< timestamp of first segment */
    int active;                 /**< whether this slot is in use */
} pending_message_t;

/** Pending messages for reassembly */
static pending_message_t pending_messages[MAX_PENDING_MESSAGES];

/**
 * @brief Test state structure.
 */
struct state {
    sr_conn_ctx_t *conn;            /**< sysrepo connection */
    sr_session_ctx_t *sess;         /**< sysrepo session */
    const struct ly_ctx *ly_ctx;    /**< libyang context */
    pid_t notifd_pid;               /**< PID of sysrepo-notifd process */
    int udp_sockfd;                 /**< UDP socket for receiving notifications */
    uint16_t udp_port;              /**< UDP port used for test */
};

/**
 * @brief Parsed UDP-Notif header.
 */
typedef struct {
    uint8_t version;
    uint8_t s_flag;
    uint8_t media_type;
    uint8_t header_len;
    uint16_t message_len;
    uint32_t publisher_id;
    uint32_t message_id;
    int has_segmentation;
    uint16_t segment_num;
    int is_last_segment;
} udp_notif_header_t;

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
 * @brief Poll a socket for available data with timeout.
 *
 * @param[in] sockfd Socket FD to poll.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @return 1 if data available, 0 on timeout, -1 on error.
 */
static int
poll_for_data(int sockfd, int timeout_ms)
{
    struct pollfd pfd;

    pfd.fd = sockfd;
    pfd.events = POLLIN;

    return poll(&pfd, 1, timeout_ms);
}

/**
 * @brief Find or create a pending message slot for reassembly.
 *
 * @param[in] publisher_id Publisher ID.
 * @param[in] message_id Message ID.
 * @param[in] media_type Media type.
 * @return Pending message slot or NULL on error.
 */
static pending_message_t *
find_or_create_pending(uint32_t publisher_id, uint32_t message_id, uint8_t media_type)
{
    pending_message_t *oldest = NULL;
    time_t oldest_time = 0;
    time_t now = time(NULL);
    int i, j;

    /* first, look for existing entry */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        if (pending_messages[i].active &&
                (pending_messages[i].publisher_id == publisher_id) &&
                (pending_messages[i].message_id == message_id)) {
            return &pending_messages[i];
        }

        /* track oldest for potential eviction */
        if (pending_messages[i].active) {
            if (!oldest || (pending_messages[i].first_received < oldest_time)) {
                oldest = &pending_messages[i];
                oldest_time = pending_messages[i].first_received;
            }
        }
    }

    /* look for empty slot */
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

    /* evict oldest if timed out */
    if (oldest && (now - oldest->first_received > SEGMENT_REASSEMBLY_TIMEOUT)) {
        TLOG_WRN("Evicting timed-out pending message (pub_id=%u, msg_id=%u)",
                oldest->publisher_id, oldest->message_id);

        /* free old segments */
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

    TLOG_ERR("No space for pending message reassembly");
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

/**
 * @brief Create UDP socket for receiving notifications.
 *
 * @param[in] port Port to listen on.
 * @return Socket FD on success, -1 on error.
 */
static int
create_udp_receiver_socket(uint16_t port)
{
    int sockfd;
    struct sockaddr_in addr;
    int opt = 1;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/**
 * @brief Receive and parse a notification from UDP socket.
 *
 * Handles both unsegmented and segmented UDP-Notif messages.
 * For segmented messages, waits for all segments and reassembles them.
 *
 * @param[in] sockfd UDP socket FD.
 * @param[in] ly_ctx libyang context for parsing.
 * @param[in] timeout_ms Timeout in milliseconds for waiting for data.
 * @param[out] notif Parsed notification (caller must free).
 * @param[out] header Optional parsed header (can be NULL).
 * @return 0 on success, 1 on timeout, -1 on error.
 */
static int
receive_notification_ext(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        struct lyd_node **notif, udp_notif_header_t *header, char *src_addr, size_t src_addr_len)
{
    uint8_t buffer[UDP_MAX_SIZE];
    ssize_t recv_len;
    udp_notif_header_t hdr;
    const uint8_t *payload;
    size_t payload_len, reassembled_len;
    struct ly_in *in = NULL;
    LYD_FORMAT format;
    pending_message_t *pending;
    char *reassembled = NULL;
    char *payload_str = NULL;
    struct sockaddr_storage src_sockaddr;
    socklen_t src_sockaddr_len;
    const void *src_ptr;
    int family;
    int r;
    int rc = -1;

    *notif = NULL;
    if (src_addr && src_addr_len) {
        src_addr[0] = '\0';
    }

receive_next:
    memset(&src_sockaddr, 0, sizeof(src_sockaddr));
    src_sockaddr_len = sizeof(src_sockaddr);

    /* poll for data with explicit timeout */
    r = poll_for_data(sockfd, timeout_ms);
    if (r < 0) {
        TLOG_ERR("poll() failed: %s", strerror(errno));
        return -1;
    }
    if (r == 0) {
        TLOG_WRN("Timeout waiting for notification");
        return 1;
    }

    recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_sockaddr, &src_sockaddr_len);
    if (recv_len < 0) {
        TLOG_ERR("recvfrom() failed: %s", strerror(errno));
        return -1;
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
        return -1;
    }

    if (header) {
        *header = hdr;
    }

    if (hdr.version != UDP_NOTIF_VERSION) {
        TLOG_ERR("Invalid UDP-Notif version: %d", hdr.version);
        return -1;
    }

    payload = buffer + hdr.header_len;
    payload_len = recv_len - hdr.header_len;

    /* handle segmentation */
    if (hdr.has_segmentation) {
        TLOG_INF("Received segment %d%s for message %u",
                hdr.segment_num, hdr.is_last_segment ? " (last)" : "", hdr.message_id);

        pending = find_or_create_pending(hdr.publisher_id, hdr.message_id, hdr.media_type);
        if (!pending) {
            TLOG_ERR("Failed to create pending message for reassembly");
            return -1;
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

        /* free the pending message slot */
        free_pending_message(pending);
    } else {
        /* non-segmented message, copy payload to null-terminated string */
        if (payload_len == 0) {
            TLOG_ERR("Empty payload");
            return -1;
        }

        payload_str = malloc(payload_len + 1);
        if (!payload_str) {
            TLOG_ERR("Memory allocation failed");
            return -1;
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
        TLOG_ERR("Unsupported media type: %d", hdr.media_type);
        goto cleanup;
    }

    if (ly_in_new_memory(payload_str, &in)) {
        TLOG_ERR("Failed to create libyang input");
        goto cleanup;
    }

    if (lyd_parse_op(ly_ctx, NULL, in, format, LYD_TYPE_NOTIF_YANG, 0, NULL, notif)) {
        TLOG_ERR("Failed to parse notification: %s", ly_err_last(ly_ctx)->msg);
        ly_in_free(in, 0);
        goto cleanup;
    }

    ly_in_free(in, 0);
    rc = 0;

cleanup:
    free(payload_str);
    return rc;
}

static int
receive_notification(int sockfd, const struct ly_ctx *ly_ctx, struct lyd_node **notif,
        udp_notif_header_t *header)
{
    return receive_notification_ext(sockfd, ly_ctx, NOTIF_TIMEOUT_MS, notif, header, NULL, 0);
}

/**
 * @brief Receive notification with custom timeout.
 */
static int
receive_notification_timeout(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        struct lyd_node **notif, udp_notif_header_t *header)
{
    return receive_notification_ext(sockfd, ly_ctx, timeout_ms, notif, header, NULL, 0);
}

/**
 * @brief Wait for a specific notification by path.
 *
 * Reads notifications from the socket until one with the expected path is found or timeout occurs.
 *
 * @param[in] sockfd UDP socket FD.
 * @param[in] ly_ctx libyang context for parsing.
 * @param[in] timeout_ms Timeout in milliseconds per receive attempt.
 * @param[in] expected_path Expected notification path.
 * @param[out] notif Parsed notification (caller must free).
 * @param[out] header Optional parsed header (can be NULL).
 * @return 0 on success, -1 on error or timeout.
 */
static int
receive_specific_notification_ext(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        const char *expected_path, struct lyd_node **notif, udp_notif_header_t *header,
        char *src_addr, size_t src_addr_len)
{
    udp_notif_header_t hdr;
    struct lyd_node *received_notif = NULL;
    int r;
    char *notif_path = NULL;
    char recv_src_addr[INET6_ADDRSTRLEN] = {0};

    while (1) {
        r = receive_notification_ext(sockfd, ly_ctx, timeout_ms, &received_notif, &hdr, recv_src_addr, sizeof(recv_src_addr));
        if (r < 0) {
            return -1;
        }

        if (!received_notif) {
            continue;
        }

        notif_path = lyd_path(received_notif, LYD_PATH_STD, NULL, 0);
        r = strcmp(notif_path, expected_path);
        free(notif_path);
        if (!r) {
            *notif = received_notif;
            if (header) {
                *header = hdr;
            }
            if (src_addr && src_addr_len) {
                strncpy(src_addr, recv_src_addr, src_addr_len - 1);
                src_addr[src_addr_len - 1] = '\0';
            }
            return 0;
        }

        /* not the expected notification, free and keep waiting */
        lyd_free_all(received_notif);
    }
}

static int
receive_specific_notification(int sockfd, const struct ly_ctx *ly_ctx, const char *expected_path,
        struct lyd_node **notif, udp_notif_header_t *header)
{
    return receive_specific_notification_ext(sockfd, ly_ctx, NOTIF_TIMEOUT_MS, expected_path, notif, header, NULL, 0);
}

/**
 * @brief Wait for a specific notification with custom timeout.
 */
static int
receive_specific_notification_timeout(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        const char *expected_path, struct lyd_node **notif, udp_notif_header_t *header)
{
    return receive_specific_notification_ext(sockfd, ly_ctx, timeout_ms, expected_path, notif, header, NULL, 0);
}

/**
 * @brief Find a direct child of a node by schema name.
 *
 * @param[in] parent Parent node.
 * @param[in] name Schema name of the child to find.
 * @return Pointer to the child, or NULL if not found.
 */
static struct lyd_node *
find_envelope_child(struct lyd_node *parent, const char *name)
{
    struct lyd_node *child;

    for (child = lyd_child(parent); child; child = child->next) {
        if (child->schema && !strcmp(child->schema->name, name)) {
            return child;
        }
    }
    return NULL;
}

/**
 * @brief Receive a UDP-Notif message and parse it as a notification envelope.
 *
 * Parses the reassembled payload with lyd_parse_data_mem (not lyd_parse_op),
 * then extracts the inner notification from the contents anydata.
 *
 * @param[in] sockfd UDP socket FD.
 * @param[in] ly_ctx libyang context for parsing.
 * @param[in] timeout_ms Timeout in milliseconds for waiting for data.
 * @param[out] env Parsed envelope tree (caller must free with lyd_free_all).
 * @param[out] notif Inner notification extracted from contents (separately allocated, caller must free with lyd_free_all).
 * @param[out] header Optional parsed header (can be NULL).
 * @param[out] src_addr Optional source address buffer (can be NULL).
 * @param[in] src_addr_len Size of src_addr buffer.
 * @return 0 on success, 1 on timeout, -1 on error.
 */
static int
receive_envelope_notification_ext(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        struct lyd_node **env, struct lyd_node **notif, udp_notif_header_t *header,
        char *src_addr, size_t src_addr_len)
{
    uint8_t buffer[UDP_MAX_SIZE];
    ssize_t recv_len;
    udp_notif_header_t hdr;
    const uint8_t *payload;
    size_t payload_len, reassembled_len;
    LYD_FORMAT format;
    pending_message_t *pending;
    struct sockaddr_storage src_sockaddr;
    socklen_t src_sockaddr_len;
    const void *src_ptr;
    struct lyd_node *contents = NULL;
    char *reassembled = NULL, *payload_str = NULL, *contents_str = NULL;
    struct ly_in *in = NULL;
    int family, r, rc = -1;

    *env = NULL;
    if (notif) {
        *notif = NULL;
    }
    if (src_addr && src_addr_len) {
        src_addr[0] = '\0';
    }

receive_next:
    memset(&src_sockaddr, 0, sizeof(src_sockaddr));
    src_sockaddr_len = sizeof(src_sockaddr);

    /* poll for data with explicit timeout */
    r = poll_for_data(sockfd, timeout_ms);
    if (r < 0) {
        TLOG_ERR("poll() failed: %s", strerror(errno));
        return -1;
    }
    if (r == 0) {
        TLOG_WRN("Timeout waiting for notification");
        return 1;
    }

    recv_len = recvfrom(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr *)&src_sockaddr, &src_sockaddr_len);
    if (recv_len < 0) {
        TLOG_ERR("recvfrom() failed: %s", strerror(errno));
        return -1;
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
        return -1;
    }

    if (header) {
        *header = hdr;
    }

    if (hdr.version != UDP_NOTIF_VERSION) {
        TLOG_ERR("Invalid UDP-Notif version: %d", hdr.version);
        return -1;
    }

    payload = buffer + hdr.header_len;
    payload_len = recv_len - hdr.header_len;

    /* handle segmentation */
    if (hdr.has_segmentation) {
        TLOG_INF("Received segment %d%s for message %u",
                hdr.segment_num, hdr.is_last_segment ? " (last)" : "", hdr.message_id);

        pending = find_or_create_pending(hdr.publisher_id, hdr.message_id, hdr.media_type);
        if (!pending) {
            TLOG_ERR("Failed to create pending message for reassembly");
            return -1;
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

        /* free the pending message slot */
        free_pending_message(pending);
    } else {
        /* non-segmented message, copy payload to null-terminated string */
        if (payload_len == 0) {
            TLOG_ERR("Empty payload");
            return -1;
        }

        payload_str = malloc(payload_len + 1);
        if (!payload_str) {
            TLOG_ERR("Memory allocation failed");
            return -1;
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
        TLOG_ERR("Unsupported media type: %d", hdr.media_type);
        goto cleanup;
    }

    /* parse as envelope (sx:structure) using lyd_parse_data_mem */
    if (lyd_parse_data_mem(ly_ctx, payload_str, format, LYD_PARSE_STRICT | LYD_PARSE_ONLY,
            0, env)) {
        TLOG_ERR("Failed to parse envelope: %s", ly_err_last(ly_ctx)->msg);
        goto cleanup;
    }

    /* find the contents anydata child and extract the inner notification */
    contents = find_envelope_child(*env, "contents");
    if (!contents || (contents->schema->nodetype != LYS_ANYDATA)) {
        TLOG_ERR("Failed to find 'contents' anydata in envelope");
        lyd_free_all(*env);
        *env = NULL;
        goto cleanup;
    }

    if (notif) {
        /* extract the anydata content as a string and parse it as a notification */
        if (lyd_any_value_str(contents, format, &contents_str)) {
            TLOG_ERR("Failed to extract anydata value: %s", ly_err_last(ly_ctx)->msg);
            lyd_free_all(*env);
            *env = NULL;
            goto cleanup;
        }

        if (ly_in_new_memory(contents_str, &in)) {
            TLOG_ERR("Failed to create libyang input");
            free(contents_str);
            lyd_free_all(*env);
            *env = NULL;
            goto cleanup;
        }

        if (lyd_parse_op(ly_ctx, NULL, in, format, LYD_TYPE_NOTIF_YANG, 0, NULL, notif)) {
            TLOG_ERR("Failed to parse inner notification: %s", ly_err_last(ly_ctx)->msg);
            ly_in_free(in, 0);
            free(contents_str);
            lyd_free_all(*env);
            *env = NULL;
            goto cleanup;
        }

        ly_in_free(in, 0);
        free(contents_str);
        contents_str = NULL;
    }

    rc = 0;

cleanup:
    free(payload_str);
    return rc;
}

static int
receive_envelope_notification(int sockfd, const struct ly_ctx *ly_ctx,
        struct lyd_node **env, struct lyd_node **notif)
{
    return receive_envelope_notification_ext(sockfd, ly_ctx, NOTIF_TIMEOUT_MS, env, notif, NULL, NULL, 0);
}

/**
 * @brief Wait for a specific notification (envelope-wrapped) by inner path.
 *
 * Reads envelope-wrapped notifications from the socket until one whose inner
 * notification matches the expected path is found or timeout occurs.
 */
static int
receive_envelope_specific_notification_ext(int sockfd, const struct ly_ctx *ly_ctx, int timeout_ms,
        const char *expected_path, struct lyd_node **env, struct lyd_node **notif)
{
    struct lyd_node *received_env = NULL;
    struct lyd_node *received_notif = NULL;
    char *notif_path = NULL;
    int r;

    while (1) {
        r = receive_envelope_notification_ext(sockfd, ly_ctx, timeout_ms, &received_env,
                &received_notif, NULL, NULL, 0);
        if (r < 0) {
            return -1;
        }
        if (r > 0) {
            /* timeout */
            return 1;
        }

        if (!received_notif) {
            continue;
        }

        notif_path = lyd_path(received_notif, LYD_PATH_STD, NULL, 0);
        r = strcmp(notif_path, expected_path);
        free(notif_path);
        if (!r) {
            *env = received_env;
            *notif = received_notif;
            return 0;
        }

        /* not the expected notification, free both and keep waiting */
        lyd_free_all(received_env);
        lyd_free_all(received_notif);
        received_env = NULL;
        received_notif = NULL;
    }
}

static int
receive_envelope_specific_notification(int sockfd, const struct ly_ctx *ly_ctx,
        const char *expected_path, struct lyd_node **env, struct lyd_node **notif)
{
    return receive_envelope_specific_notification_ext(sockfd, ly_ctx, NOTIF_TIMEOUT_MS, expected_path, env, notif);
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

static int
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

/**
 * @brief Drain all pending notifications from the socket.
 *
 * Reads and discards all notifications until no more data is available.
 * Uses poll() with a short timeout for robustness on slow machines.
 *
 * @param[in] sockfd UDP socket FD.
 */
static void
drain_notifications(int sockfd)
{
    uint8_t buffer[UDP_MAX_SIZE];
    ssize_t recv_len;
    int count;
    int poll_ret;

    count = 0;

    /* read and discard all pending notifications */
    while (1) {
        poll_ret = poll_for_data(sockfd, DRAIN_TIMEOUT_MS);
        if (poll_ret <= 0) {
            break;
        }

        recv_len = recv(sockfd, buffer, sizeof(buffer), 0);
        if (recv_len <= 0) {
            break;
        }
        count++;
    }

    if (count > 0) {
        TLOG_INF("Drained %d pending notification(s)", count);
    }
}

/**
 * @brief Install required YANG modules for testing.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
install_test_modules(sr_conn_ctx_t *conn)
{
    const char *schema_paths[] = {
        SN_YANG_DIR "/ietf-interfaces@2018-02-20.yang",
        SN_YANG_DIR "/iana-if-type@2014-05-08.yang",
        SN_YANG_DIR "/ietf-ip@2018-02-22.yang",
        SN_YANG_DIR "/ietf-network-instance@2019-01-21.yang",
        SN_YANG_DIR "/ietf-restconf@2017-01-26.yang",
        SN_YANG_DIR "/ietf-subscribed-notifications@2019-09-09.yang",
        SN_YANG_DIR "/ietf-subscribed-notif-receivers@2024-02-01.yang",
        SN_YANG_DIR "/ietf-crypto-types@2024-10-10.yang",
        SN_YANG_DIR "/iana-tls-cipher-suite-algs@2024-03-16.yang",
        SN_YANG_DIR "/ietf-keystore@2024-10-10.yang",
        SN_YANG_DIR "/ietf-truststore@2024-10-10.yang",
        SN_YANG_DIR "/ietf-tls-common@2024-10-10.yang",
        SN_YANG_DIR "/ietf-tls-client@2024-03-16.yang",
        SN_YANG_DIR "/ietf-udp-client@2025-05-14.yang",
        SN_YANG_DIR "/ietf-udp-notif-transport@2025-06-04.yang",
        TESTS_SRC_DIR "/files/ietf-yp-notification@2025-12-24.yang",
        TESTS_SRC_DIR "/files/ietf-yp-observation@2025-12-24.yang",
        TESTS_SRC_DIR "/files/test.yang",
        NULL
    };
    const char *sub_ntf_feats[] = {"configured", "xpath", "replay", "subtree", "encode-xml", "encode-json", NULL};
    const char *yp_notif_feats[] = {"hostname-sequence-number", NULL};
    const char **features[] = {
        NULL, NULL, NULL, NULL, NULL,  /* interfaces, iana-if-type, ip, network-instance, restconf */
        sub_ntf_feats,                 /* ietf-subscribed-notifications */
        NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,  /* other modules */
        yp_notif_feats,                /* ietf-yp-notification */
        NULL,                          /* ietf-yp-observation */
        NULL                           /* test.yang */
    };

    return sr_install_modules(conn, schema_paths, SN_YANG_DIR, features);
}

/**
 * @brief Remove test YANG modules.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
remove_test_modules(sr_conn_ctx_t *conn)
{
    const char *module_names[] = {
        "test",
        "ietf-udp-notif-transport",
        "ietf-udp-client",
        "ietf-tls-client",
        "ietf-tls-common",
        "ietf-truststore",
        "ietf-keystore",
        "iana-tls-cipher-suite-algs",
        "ietf-crypto-types",
        "ietf-subscribed-notif-receivers",
        "ietf-yp-observation",
        "ietf-yp-notification",
        "ietf-yang-push",
        "ietf-notification-capabilities",
        "ietf-system-capabilities",
        "ietf-subscribed-notifications",
        "ietf-restconf",
        "ietf-network-instance",
        "ietf-ip",
        "iana-if-type",
        "ietf-interfaces",
        NULL
    };

    return sr_remove_modules(conn, module_names, 0);
}

/**
 * @brief Start sysrepo-notifd daemon.
 *
 * @param[out] pid PID of started daemon.
 * @return 0 on success, -1 on failure.
 */
static int
start_notifd(pid_t *pid)
{
    pid_t child_pid;
    int pipefd[2];
    struct pollfd pfd;
    int i, status, ret;
    char c;

    /* create pipe with CLOEXEC so exec() automatically closes the write end */
    if (pipe2(pipefd, O_CLOEXEC) < 0) {
        return -1;
    }

    child_pid = fork();
    if (child_pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    if (child_pid == 0) {
        /* child process - close read end, keep write end for failure signaling */
        close(pipefd[0]);

        execlp(NOTIFD_PATH, "sysrepo-notifd", "-d", "-v", "info", "-s", SCHEMA_DIR, (char *)NULL);

        /* exec failed - signal parent by writing to pipe before exiting */
        c = 1;
        write(pipefd[1], &c, 1);
        _exit(1);
    }

    /* parent - close write end so only the child holds it */
    close(pipefd[1]);

    /*
     * Poll the read end:
     * - POLLIN means child wrote to pipe → exec failed
     * - POLLHUP means child's write end closed → exec succeeded (CLOEXEC kicked in)
     * - timeout means something unexpected
     */
    pfd.fd = pipefd[0];
    pfd.events = POLLIN;
    ret = poll(&pfd, 1, 3000);

    close(pipefd[0]);

    if (ret < 0) {
        TLOG_ERR("poll() failed while waiting for daemon exec: %s", strerror(errno));
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        return -1;
    }

    if (ret == 0) {
        TLOG_ERR("Timeout waiting for sysrepo-notifd exec");
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);
        return -1;
    }

    if (pfd.revents & POLLIN) {
        /* exec failed - child wrote error byte before _exit() */
        waitpid(child_pid, &status, 0);
        TLOG_ERR("sysrepo-notifd exec failed with status %d", status);
        return -1;
    }

    /* POLLHUP - exec succeeded, daemon binary is now running */

    /* brief crash detection: if it dies within 200ms, report error */
    for (i = 0; i < 10; i++) {
        usleep(20000);
        if (waitpid(child_pid, &status, WNOHANG) != 0) {
            TLOG_ERR("sysrepo-notifd exited prematurely with status %d", status);
            return -1;
        }
    }

    *pid = child_pid;
    return 0;
}

/**
 * @brief Stop sysrepo-notifd daemon.
 *
 * @param[in] pid PID of daemon to stop.
 */
static void
stop_notifd(pid_t pid)
{
    int status;

    if (pid > 0) {
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
    }
}

/**
 * @brief Set common subscription fields (stream, transport, receiver-instance-ref).
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] recv_inst_name Receiver instance name to reference.
 * @return 0 on success, error code on failure.
 */
static int
_set_sub_common(sr_session_ctx_t *sess, uint32_t sub_id, const char *stream,
        const char *recv_inst_name)
{
    int rc;
    char path[512];

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']/stream", sub_id);
    rc = sr_set_item_str(sess, path, stream, NULL, 0);
    if (rc) {
        return rc;
    }

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']/transport", sub_id);
    rc = sr_set_item_str(sess, path, "ietf-udp-notif-transport:udp-notif", NULL, 0);
    if (rc) {
        return rc;
    }

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']"
            "/receivers/receiver[name='recv1']/ietf-subscribed-notif-receivers:receiver-instance-ref", sub_id);
    rc = sr_set_item_str(sess, path, recv_inst_name, NULL, 0);
    if (rc) {
        return rc;
    }

    return SR_ERR_OK;
}

/**
 * @brief Create a configured subscription via sysrepo edit.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] filter Optional XPath filter.
 * @param[in] recv_inst_name Receiver instance name to reference.
 * @return 0 on success, error code on failure.
 */
static int
create_subscription(sr_session_ctx_t *sess, uint32_t sub_id, const char *stream,
        const char *filter, const char *recv_inst_name)
{
    int rc;
    char path[512];

    rc = _set_sub_common(sess, sub_id, stream, recv_inst_name);
    if (rc) {
        return rc;
    }

    if (filter) {
        snprintf(path, sizeof(path),
                "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']/stream-xpath-filter", sub_id);
        rc = sr_set_item_str(sess, path, filter, NULL, 0);
        if (rc) {
            return rc;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Create a configured subscription with subtree filter via sysrepo edit.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] subtree_filter_xml Subtree filter in XML format.
 * @param[in] recv_inst_name Receiver instance name to reference.
 * @return 0 on success, error code on failure.
 */
static int
create_subscription_subtree(sr_session_ctx_t *sess, uint32_t sub_id, const char *stream,
        const char *subtree_filter_xml, const char *recv_inst_name)
{
    int rc;
    char path[512];
    sr_val_t val;

    rc = _set_sub_common(sess, sub_id, stream, recv_inst_name);
    if (rc) {
        return rc;
    }

    if (subtree_filter_xml) {
        memset(&val, 0, sizeof(val));
        val.type = SR_ANYDATA_T;
        val.data.anydata_val = (char *)subtree_filter_xml;

        snprintf(path, sizeof(path),
                "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']/stream-subtree-filter", sub_id);
        rc = sr_set_item(sess, path, &val, 0);
        if (rc) {
            return rc;
        }
    }

    return SR_ERR_OK;
}

/**
 * @brief Create a UDP receiver instance via sysrepo edit.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] name Receiver instance name.
 * @param[in] address Remote address.
 * @param[in] port Remote port.
 * @return 0 on success, error code on failure.
 */
static int
create_receiver_instance(sr_session_ctx_t *sess, const char *name, const char *address, uint16_t port)
{
    int rc;
    char path[512], port_str[16];

    snprintf(port_str, sizeof(port_str), "%u", port);

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions"
            "/ietf-subscribed-notif-receivers:receiver-instances"
            "/receiver-instance[name='%s']"
            "/ietf-udp-notif-transport:udp-notif-receiver/remote-address", name);
    rc = sr_set_item_str(sess, path, address, NULL, 0);
    if (rc) {
        return rc;
    }

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions"
            "/ietf-subscribed-notif-receivers:receiver-instances"
            "/receiver-instance[name='%s']"
            "/ietf-udp-notif-transport:udp-notif-receiver/remote-port", name);
    rc = sr_set_item_str(sess, path, port_str, NULL, 0);
    if (rc) {
        return rc;
    }

    return SR_ERR_OK;
}

/**
 * @brief Delete a configured subscription.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @return 0 on success, error code on failure.
 */
static int
delete_subscription(sr_session_ctx_t *sess, uint32_t sub_id)
{
    char path[256];

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']", sub_id);
    return sr_delete_item(sess, path, 0);
}

/**
 * @brief Delete a receiver instance.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] name Receiver instance name.
 * @return 0 on success, error code on failure.
 */
static int
delete_receiver_instance(sr_session_ctx_t *sess, const char *name)
{
    char path[256];

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions"
            "/ietf-subscribed-notif-receivers:receiver-instances"
            "/receiver-instance[name='%s']", name);
    return sr_delete_item(sess, path, 0);
}

/**
 * @brief Create a named XPath stream filter.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] filter_name Name of the filter.
 * @param[in] xpath_filter XPath filter expression.
 * @return 0 on success, error code on failure.
 */
static int
create_xpath_stream_filter(sr_session_ctx_t *sess, const char *filter_name, const char *xpath_filter)
{
    int rc;
    char path[512];

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='%s']/stream-xpath-filter",
            filter_name);
    rc = sr_set_item_str(sess, path, xpath_filter, NULL, 0);

    return rc;
}

/**
 * @brief Create a named subtree stream filter.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] filter_name Name of the filter.
 * @param[in] subtree_filter_xml Subtree filter in XML format.
 * @return 0 on success, error code on failure.
 */
static int
create_subtree_stream_filter(sr_session_ctx_t *sess, const char *filter_name, const char *subtree_filter_xml)
{
    int rc;
    char path[512];
    sr_val_t val;

    memset(&val, 0, sizeof(val));
    val.type = SR_ANYDATA_T;
    val.data.anydata_val = (char *)subtree_filter_xml;

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='%s']/stream-subtree-filter",
            filter_name);
    rc = sr_set_item(sess, path, &val, 0);

    return rc;
}

/**
 * @brief Delete a named stream filter.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] filter_name Name of the filter.
 * @return 0 on success, error code on failure.
 */
static int
delete_stream_filter(sr_session_ctx_t *sess, const char *filter_name)
{
    char path[256];

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='%s']", filter_name);
    return sr_delete_item(sess, path, 0);
}

/**
 * @brief Create a subscription with a filter name reference.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] filter_name Name of the filter to reference.
 * @param[in] recv_inst_name Receiver instance name to reference.
 * @return 0 on success, error code on failure.
 */
static int
create_subscription_filter_ref(sr_session_ctx_t *sess, uint32_t sub_id, const char *stream,
        const char *filter_name, const char *recv_inst_name)
{
    int rc;
    char path[512];

    rc = _set_sub_common(sess, sub_id, stream, recv_inst_name);
    if (rc) {
        return rc;
    }

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']/stream-filter-name", sub_id);
    rc = sr_set_item_str(sess, path, filter_name, NULL, 0);
    if (rc) {
        return rc;
    }

    return SR_ERR_OK;
}

/**
 * @brief Setup function - install modules, start daemon, create socket.
 */
static int
setup(void **state)
{
    struct state *st;
    int rc;

    st = calloc(1, sizeof *st);
    if (!st) {
        return 1;
    }
    *state = st;

    /* connect to sysrepo */
    rc = sr_connect(0, &st->conn);
    if (rc) {
        TLOG_ERR("sr_connect failed: %s", sr_strerror(rc));
        return 1;
    }

    /* install test modules */
    rc = install_test_modules(st->conn);
    if (rc && (rc != SR_ERR_EXISTS)) {
        TLOG_ERR("install_test_modules failed: %s", sr_strerror(rc));
        return 1;
    }

    /* get libyang context */
    st->ly_ctx = sr_acquire_context(st->conn);

    /* start session */
    rc = sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);
    if (rc) {
        TLOG_ERR("sr_session_start failed: %s", sr_strerror(rc));
        return 1;
    }

    /* find available port */
    st->udp_port = TEST_UDP_PORT;

    /* create UDP receiver socket */
    st->udp_sockfd = create_udp_receiver_socket(st->udp_port);
    if (st->udp_sockfd < 0) {
        TLOG_ERR("Failed to create UDP socket");
        return 1;
    }

    /* start sysrepo-notifd */
    if (start_notifd(&st->notifd_pid)) {
        TLOG_ERR("Failed to start sysrepo-notifd");
        return 1;
    }

    return 0;
}

/**
 * @brief Teardown function - stop daemon, cleanup.
 */
static int
teardown(void **state)
{
    struct state *st = *state;
    int ret = 0, i;

    /* stop sysrepo-notifd */
    stop_notifd(st->notifd_pid);

    /* close UDP socket */
    if (st->udp_sockfd >= 0) {
        close(st->udp_sockfd);
    }

    /* cleanup pending messages */
    for (i = 0; i < MAX_PENDING_MESSAGES; i++) {
        free_pending_message(&pending_messages[i]);
    }

    /* release context */
    if (st->ly_ctx) {
        sr_release_context(st->conn);
    }

    /* remove test modules */
    if (st->conn) {
        ret = remove_test_modules(st->conn);
        sr_disconnect(st->conn);
    }

    free(st);
    return ret;
}

/**
 * @brief Clear any existing subscriptions and unread notifications before each test to ensure a clean state.
 *
 * Also disables the notification envelope to ensure every test starts in the
 * default (bare) egress format.
 */
static int
clear_subs_notifs(void **state)
{
    struct state *st = *state;

    /* disable envelope if it was left enabled by a previous test */
    sr_set_item_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/ietf-yp-notification:enable-notification-envelope",
            "false", NULL, 0);
    sr_delete_item(st->sess, "/ietf-subscribed-notifications:subscriptions", 0);
    sr_apply_changes(st->sess, 0);

    /* drain any remaining notifications */
    drain_notifications(st->udp_sockfd);
    return 0;
}

/**
 * @brief Enable or disable the notification envelope.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] enabled 1 to enable, 0 to disable.
 * @return 0 on success, error code on failure.
 */
static int
set_envelope_enabled(sr_session_ctx_t *sess, int enabled)
{
    int ret;

    ret = sr_set_item_str(sess,
            "/ietf-subscribed-notifications:subscriptions/ietf-yp-notification:enable-notification-envelope",
            enabled ? "true" : "false", NULL, 0);
    if (ret) {
        return ret;
    }
    return sr_apply_changes(sess, 0);
}

/**
 * @brief Create a receiver instance and subscription, then apply changes.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] port UDP port for the receiver.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] xpath_filter Optional XPath filter (can be NULL).
 */
static void
setup_sub(sr_session_ctx_t *sess, uint16_t port, uint32_t sub_id,
        const char *stream, const char *xpath_filter)
{
    int ret;

    ret = create_receiver_instance(sess, "test-recv", "127.0.0.1", port);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_subscription(sess, sub_id, stream, xpath_filter, "test-recv");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

/**
 * @brief Create a receiver instance and subscription with subtree filter, then apply changes.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] port UDP port for the receiver.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] subtree_filter_xml Subtree filter in XML format.
 */
static void
setup_sub_subtree(sr_session_ctx_t *sess, uint16_t port, uint32_t sub_id,
        const char *stream, const char *subtree_filter_xml)
{
    int ret;

    ret = create_receiver_instance(sess, "test-recv", "127.0.0.1", port);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_subscription_subtree(sess, sub_id, stream, subtree_filter_xml, "test-recv");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

/**
 * @brief Create a receiver instance, XPath stream filter, and filter-ref subscription, then apply changes.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] port UDP port for the receiver.
 * @param[in] sub_id Subscription ID.
 * @param[in] stream Stream name.
 * @param[in] filter_name Name of the XPath stream filter.
 * @param[in] xpath_filter XPath filter expression.
 */
static void
setup_sub_filter_ref(sr_session_ctx_t *sess, uint16_t port, uint32_t sub_id,
        const char *stream, const char *filter_name, const char *xpath_filter)
{
    int ret;

    ret = create_receiver_instance(sess, "test-recv", "127.0.0.1", port);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_xpath_stream_filter(sess, filter_name, xpath_filter);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_subscription_filter_ref(sess, sub_id, stream, filter_name, "test-recv");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
}

/**
 * @brief Delete a subscription and its receiver instance, then apply changes.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 */
static void
cleanup_sub(sr_session_ctx_t *sess, uint32_t sub_id)
{
    delete_subscription(sess, sub_id);
    delete_receiver_instance(sess, "test-recv");
    sr_apply_changes(sess, 0);
}

/**
 * @brief Read a single operational data leaf value.
 *
 * Switches to operational datastore, reads the leaf at the given XPath,
 * and switches back to running datastore. Caller must free the returned string.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] xpath XPath of the leaf to read.
 * @return Newly allocated string with the leaf value, or NULL on error.
 */
static char *
get_oper_leaf_str(sr_session_ctx_t *sess, const char *xpath)
{
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char *value = NULL;
    int ret;

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(sess, xpath, 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    assert_non_null(data->tree);

    assert_int_equal(lyd_find_path(data->tree, xpath, 0, &node), LY_SUCCESS);
    assert_non_null(node);
    value = strdup(lyd_get_value(node));

    sr_release_data(data);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    return value;
}

/**
 * @brief Read an operational counter value without asserting.
 *
 * Similar to get_oper_leaf_str but returns the value as a uint64_t
 * and returns an error code instead of asserting on failure.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] xpath XPath of the leaf to read.
 * @param[out] counter Parsed counter value.
 * @return 0 on success, -1 on error.
 */
static int
get_oper_counter(sr_session_ctx_t *sess, const char *xpath, uint64_t *counter)
{
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char *value = NULL;
    int ret;

    ret = sr_session_switch_ds(sess, SR_DS_OPERATIONAL);
    if (ret) {
        return -1;
    }

    ret = sr_get_data(sess, xpath, 0, 0, 0, &data);
    if (ret || !data || !data->tree) {
        if (data) {
            sr_release_data(data);
        }
        sr_session_switch_ds(sess, SR_DS_RUNNING);
        return -1;
    }

    if (lyd_find_path(data->tree, xpath, 0, &node) || !node) {
        sr_release_data(data);
        sr_session_switch_ds(sess, SR_DS_RUNNING);
        return -1;
    }

    value = strdup(lyd_get_value(node));
    *counter = strtoull(value, NULL, 10);
    free(value);

    sr_release_data(data);

    ret = sr_session_switch_ds(sess, SR_DS_RUNNING);
    if (ret) {
        return -1;
    }

    return 0;
}

/**
 * @brief Wait for excluded-event-records to increment above a baseline.
 *
 * Polls the operational datastore counter in a loop until it exceeds
 * the baseline value or the timeout expires. Used instead of waiting
 * for a socket timeout to prove that a notification was filtered.
 *
 * @param[in] sess Sysrepo session.
 * @param[in] sub_id Subscription ID.
 * @param[in] baseline Baseline counter value.
 * @param[in] timeout_ms Total timeout in milliseconds.
 * @return 0 if counter incremented, -1 on timeout.
 */
static int
wait_for_excluded_records_increment(sr_session_ctx_t *sess, uint32_t sub_id,
        uint64_t baseline, int timeout_ms)
{
    char xpath[512];
    uint64_t current;
    int elapsed_ms = 0;
    int ret;

    snprintf(xpath, sizeof(xpath),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='%u']"
            "/receivers/receiver[name='recv1']/excluded-event-records", sub_id);

    while (elapsed_ms < timeout_ms) {
        usleep(COUNTER_POLL_MS * 1000);
        elapsed_ms += COUNTER_POLL_MS;

        ret = get_oper_counter(sess, xpath, &current);
        if (ret) {
            continue;
        }

        if (current > baseline) {
            return 0;
        }
    }

    return -1;
}

/* ========== TESTS ========== */

/**
 * @brief Test: Create subscription and receive subscription-started notification.
 */
static void
test_subscription_started(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    udp_notif_header_t header;
    int ret;

    TLOG_INF("Creating receiver instance and subscription...");

    setup_sub(st->sess, st->udp_port, 1, "NETCONF", NULL);

    TLOG_INF("Waiting for subscription-started notification...");

    /* receive notification */
    ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, &header);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    /* verify it's a subscription-started notification */
    assert_string_equal(notif->schema->name, "subscription-started");

    /* verify header fields */
    assert_int_equal(header.version, UDP_NOTIF_VERSION);
    assert_int_equal(header.s_flag, 0);
    assert_true(header.media_type == UDP_NOTIF_MT_JSON || header.media_type == UDP_NOTIF_MT_XML);

    TLOG_INF("Received subscription-started notification successfully");

    lyd_free_all(notif);

    cleanup_sub(st->sess, 1);
}

/**
 * @brief Test: Delete subscription and receive subscription-terminated notification.
 */
static void
test_subscription_terminated(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    TLOG_INF("Creating receiver instance and subscription...");

    setup_sub(st->sess, st->udp_port, 2, "NETCONF", NULL);

    /* receive subscription-started notification first */
    ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, NULL);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Deleting subscription...");

    /* delete subscription */
    ret = delete_subscription(st->sess, 2);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-terminated notification...");

    /* receive notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-terminated", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received subscription-terminated notification successfully");

    lyd_free_all(notif);

    delete_receiver_instance(st->sess, "test-recv");
    sr_apply_changes(st->sess, 0);
}

/**
 * @brief Test: Modify subscription filter and receive subscription-modified notification.
 */
static void
test_subscription_modified(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    int ret;

    TLOG_INF("Creating receiver instance and subscription...");

    setup_sub(st->sess, st->udp_port, 3, "NETCONF", "/ietf-netconf-notifications:*");

    TLOG_INF("Modifying subscription filter...");

    /* modify the filter */
    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='3']/stream-xpath-filter");
    ret = sr_set_item_str(st->sess, path, "/ietf-netconf-notifications:netconf-config-change", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-modified notification...");

    /* receive notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received subscription-modified notification successfully");

    lyd_free_all(notif);

    cleanup_sub(st->sess, 3);
}

/**
 * @brief Test: Multiple subscriptions to the same receiver.
 */
static void
test_multiple_subscriptions(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret, i;
    int started_count = 0;

    TLOG_INF("Creating receiver instance and multiple subscriptions...");

    /* create receiver */
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    /* create 3 subscriptions */
    for (i = 1; i <= 3; i++) {
        ret = create_subscription(st->sess, 10 + i, "NETCONF", NULL, "test-recv");
        assert_int_equal(ret, SR_ERR_OK);
    }

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-started notifications...");

    /* receive all subscription-started notifications */
    for (i = 0; i < 3; i++) {
        ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, NULL);
        assert_int_equal(ret, 0);
        assert_non_null(notif);
        if (strcmp(notif->schema->name, "subscription-started") == 0) {
            started_count++;
        }
        lyd_free_all(notif);
        notif = NULL;
    }

    assert_int_equal(started_count, 3);
    TLOG_INF("Received %d subscription-started notifications", started_count);

    /* cleanup */
    for (i = 1; i <= 3; i++) {
        delete_subscription(st->sess, 10 + i);
    }
    delete_receiver_instance(st->sess, "test-recv");
    sr_apply_changes(st->sess, 0);
}

/**
 * @brief Test: netconf-config-change notification through configured subscription.
 */
static void
test_config_change_notification(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    TLOG_INF("Creating subscription for netconf-config-change...");

    setup_sub(st->sess, st->udp_port, 20, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    TLOG_INF("Making configuration change to trigger notification...");

    /* make a configuration change */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "67", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for netconf-config-change notification...");

    /* try to receive config-change notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received netconf-config-change notification successfully");

    /* cleanup */
    lyd_free_all(notif);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 20);
}

/**
 * @brief Test: UDP-Notif header validation.
 */
static void
test_udp_notif_header(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    udp_notif_header_t header;
    int ret;

    TLOG_INF("Creating subscription to test UDP-Notif header...");

    setup_sub(st->sess, st->udp_port, 30, "NETCONF", NULL);

    /* receive notification and check header */
    ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, &header);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    /* verify UDP-Notif header fields */
    assert_int_equal(header.version, UDP_NOTIF_VERSION);

    /* standard space */
    assert_int_equal(header.s_flag, 0);
    assert_true(header.media_type == UDP_NOTIF_MT_JSON || header.media_type == UDP_NOTIF_MT_XML);

    /* no options */
    assert_int_equal(header.header_len, UDP_NOTIF_HDR_SIZE);
    assert_true(header.message_len > UDP_NOTIF_HDR_SIZE);
    assert_true(header.publisher_id > 0);
    assert_true(header.message_id > 0);

    TLOG_INF("UDP-Notif header validated: version=%d, MT=%d, pub_id=%u, msg_id=%u",
            header.version, header.media_type, header.publisher_id, header.message_id);

    lyd_free_all(notif);

    cleanup_sub(st->sess, 30);
}

/**
 * @brief Test: Message ID incrementing.
 */
static void
test_message_id_increment(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    udp_notif_header_t header1, header2;
    int ret;

    TLOG_INF("Testing message ID incrementing...");

    setup_sub(st->sess, st->udp_port, 40, "NETCONF", NULL);

    /* receive first notification */
    ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, &header1);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    /* delete and re-create to generate another notification */
    delete_subscription(st->sess, 40);
    sr_apply_changes(st->sess, 0);

    /* receive second notification (subscription-terminated) */
    ret = receive_notification(st->udp_sockfd, st->ly_ctx, &notif, &header2);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    /* message ID should have incremented */
    assert_true(header2.message_id > header1.message_id);
    TLOG_INF("Message ID incremented from %u to %u", header1.message_id, header2.message_id);

    /* cleanup */
    delete_receiver_instance(st->sess, "test-recv");
    sr_apply_changes(st->sess, 0);
}

/**
 * @brief Test: XPath filter that matches notifications.
 *
 * Creates a subscription with an XPath filter that matches netconf-config-change
 * notifications and verifies that matching notifications are received.
 */
static void
test_xpath_filter_match(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    TLOG_INF("Testing XPath filter that matches notifications...");

    setup_sub(st->sess, st->udp_port, 50, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    TLOG_INF("Making configuration change to trigger notification...");

    /* make a configuration change - this should produce a netconf-config-change notification */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "42", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for netconf-config-change notification (should match filter)...");

    /* the XPath filter should match and we should receive the notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received netconf-config-change notification - XPath filter matched successfully");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 50);
}

/**
 * @brief Test: XPath filter that does not match notifications.
 *
 * Creates a subscription with an XPath filter that filters out notifications
 * based on content (e.g., datastore type) and verifies behavior.
 */
static void
test_xpath_filter_nomatch(void **state)
{
    struct state *st = *state;
    uint64_t excluded_baseline;
    int ret;

    TLOG_INF("Testing XPath filter that should not match...");

    setup_sub(st->sess, st->udp_port, 51, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change[datastore='startup']");

    /* discard notifs that we don't care about */
    drain_notifications(st->udp_sockfd);

    /* read baseline excluded-event-records counter */
    ret = get_oper_counter(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='51']"
            "/receivers/receiver[name='recv1']/excluded-event-records", &excluded_baseline);
    assert_int_equal(ret, 0);

    TLOG_INF("Making configuration change to running datastore...");

    /* make a configuration change to running datastore */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "55", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for excluded-event-records to increment (notification was filtered)...");

    /* wait for excluded-event-records to increment, proving the notification was filtered */
    ret = wait_for_excluded_records_increment(st->sess, 51, excluded_baseline, COUNTER_WAIT_MS);
    assert_int_equal(ret, 0);

    TLOG_INF("excluded-event-records incremented - XPath filter correctly filtered out the notification");

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 51);
}

/**
 * @brief Test: XPath filter with edit target content filtering.
 *
 * Creates a subscription with an XPath filter that matches based on the
 * target path in the edit list of netconf-config-change notifications.
 */
static void
test_xpath_filter_edit_target(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    uint64_t excluded_baseline;
    int ret;

    TLOG_INF("Testing XPath filter matching edit target...");

    setup_sub(st->sess, st->udp_port, 52, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change[edit/target=\"/test:test-leaf\"]");

    /* discard notifs that we don't care about */
    drain_notifications(st->udp_sockfd);

    /* read baseline excluded-event-records counter */
    ret = get_oper_counter(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='52']"
            "/receivers/receiver[name='recv1']/excluded-event-records", &excluded_baseline);
    assert_int_equal(ret, 0);

    TLOG_INF("Making configuration change to a different target...");

    /* change test:cont/dflt-leaf - this should NOT match the filter since the target is different */
    ret = sr_set_item_str(st->sess, "/test:cont/dflt-leaf", "67", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for excluded-event-records to increment (notification was filtered)...");

    /* wait for excluded-event-records to increment, proving the notification was filtered */
    ret = wait_for_excluded_records_increment(st->sess, 52, excluded_baseline, COUNTER_WAIT_MS);
    assert_int_equal(ret, 0);

    TLOG_INF("excluded-event-records incremented - XPath filter correctly filtered out the notification based on edit target");

    TLOG_INF("Making configuration change to test:test-leaf...");

    /* change test:test-leaf - this should match the filter */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "77", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for notification with matching edit target...");

    /* should receive notification since edit target matches */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received notification - XPath filter with edit/target matched successfully");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 52);
}

/**
 * @brief Test: Subtree filter that matches notifications.
 *
 * Creates a subscription with a subtree filter that matches netconf-config-change
 * notifications and verifies that matching notifications are received.
 */
static void
test_subtree_filter_match(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    /*
     * subtree filter that matches netconf-config-change notifications
     * an empty element means "select this notification type"
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\"/>";

    TLOG_INF("Testing subtree filter that matches notifications...");

    setup_sub_subtree(st->sess, st->udp_port, 60, "NETCONF", subtree_filter);

    TLOG_INF("Making configuration change to trigger notification...");

    /* make a configuration change */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "88", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for netconf-config-change notification (should match subtree filter)...");

    /* should receive notification since subtree filter matches */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received netconf-config-change notification - subtree filter matched successfully");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 60);
}

/**
 * @brief Test: Subtree filter that does not match notifications.
 *
 * Creates a subscription with a subtree filter that filters out notifications
 * based on content and verifies that non-matching notifications are not received.
 */
static void
test_subtree_filter_nomatch(void **state)
{
    struct state *st = *state;
    uint64_t excluded_baseline;
    int ret;

    /*
     * subtree filter that matches only netconf-config-change with datastore=startup
     * we're changing running, so this should NOT match
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>startup</datastore>"
            "</netconf-config-change>";

    TLOG_INF("Testing subtree filter that should not match...");

    setup_sub_subtree(st->sess, st->udp_port, 61, "NETCONF", subtree_filter);

    /* discard notifs that we don't care about */
    drain_notifications(st->udp_sockfd);

    /* read baseline excluded-event-records counter */
    ret = get_oper_counter(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='61']"
            "/receivers/receiver[name='recv1']/excluded-event-records", &excluded_baseline);
    assert_int_equal(ret, 0);

    TLOG_INF("Making configuration change to running datastore...");

    /* make a configuration change to running datastore */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "99", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for excluded-event-records to increment (notification was filtered)...");

    /* wait for excluded-event-records to increment, proving the notification was filtered */
    ret = wait_for_excluded_records_increment(st->sess, 61, excluded_baseline, COUNTER_WAIT_MS);
    assert_int_equal(ret, 0);

    TLOG_INF("excluded-event-records incremented - subtree filter correctly filtered out the notification");

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 61);
}

/**
 * @brief Test: Subtree filter with containment node filtering.
 *
 * Creates a subscription with a subtree filter that uses containment nodes
 * to match specific notification content.
 */
static void
test_subtree_filter_containment(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    uint64_t excluded_baseline;
    int ret;

    /*
     * subtree filter that matches netconf-config-change with datastore=running
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    TLOG_INF("Testing subtree filter with containment node...");

    setup_sub_subtree(st->sess, st->udp_port, 62, "NETCONF", subtree_filter);

    /* discard notifs that we don't care about */
    drain_notifications(st->udp_sockfd);

    /* read baseline excluded-event-records counter */
    ret = get_oper_counter(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='62']"
            "/receivers/receiver[name='recv1']/excluded-event-records", &excluded_baseline);
    assert_int_equal(ret, 0);

    TLOG_INF("Making configuration change to startup datastore...");

    /* make a configuration change to startup datastore - this should NOT match since the filter is for datastore=running */
    ret = sr_session_switch_ds(st->sess, SR_DS_STARTUP);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "100", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* switch back to running before reading operational data */
    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for excluded-event-records to increment (notification was filtered)...");

    /* wait for excluded-event-records to increment, proving the notification was filtered */
    ret = wait_for_excluded_records_increment(st->sess, 62, excluded_baseline, COUNTER_WAIT_MS);
    assert_int_equal(ret, 0);

    TLOG_INF("excluded-event-records incremented - subtree filter correctly filtered out the notification based on datastore");

    TLOG_INF("Making configuration change to running datastore...");

    /* make a configuration change to running datastore - should match */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "111", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for notification matching subtree containment filter...");

    /* should receive notification since we're changing running datastore */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received notification - subtree containment filter matched successfully");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 62);
}

/**
 * @brief Test: Subscription with XPath filter reference (stream-filter-name).
 *
 * Creates a named XPath filter, then creates a subscription that references
 * it by name, and verifies that matching notifications are received.
 */
static void
test_filter_ref_xpath_match(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    TLOG_INF("Testing subscription with XPath filter reference...");

    setup_sub_filter_ref(st->sess, st->udp_port, 70, "NETCONF", "my-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='running']");

    /* drain subscription-started notification */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Making configuration change to running datastore to trigger notification...");

    /* make a configuration change to running datastore */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "200", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for netconf-config-change notification (should match xpath filter ref for datastore=running)...");

    /* should receive notification since xpath filter reference matches running datastore */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received netconf-config-change notification - XPath filter reference with datastore predicate worked");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    delete_stream_filter(st->sess, "my-xpath-filter");
    cleanup_sub(st->sess, 70);
}

/**
 * @brief Test: Subscription with subtree filter reference (stream-filter-name).
 *
 * Creates a named subtree filter, then creates a subscription that references
 * it by name, and verifies that matching notifications are received.
 */
static void
test_filter_ref_subtree_match(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    int ret;

    /*
     * subtree filter that matches netconf-config-change notifications
     * with datastore=running - uses containment node filtering
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    TLOG_INF("Testing subscription with subtree filter reference...");

    /* create receiver instance */
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a named subtree filter */
    ret = create_subtree_stream_filter(st->sess, "my-subtree-filter", subtree_filter);
    assert_int_equal(ret, SR_ERR_OK);

    /* create subscription referencing the filter by name */
    ret = create_subscription_filter_ref(st->sess, 71, "NETCONF", "my-subtree-filter", "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* drain subscription-started notification */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Making configuration change to running datastore to trigger notification...");

    /* make a configuration change to running datastore */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "201", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for netconf-config-change notification (should match subtree filter ref for datastore=running)...");

    /* should receive notification since subtree filter reference matches running datastore */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received netconf-config-change notification - subtree filter reference with containment worked");

    lyd_free_all(notif);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    delete_stream_filter(st->sess, "my-subtree-filter");
    cleanup_sub(st->sess, 71);
}

/**
 * @brief Test: Modifying a referenced XPath filter triggers subscription-modified.
 *
 * Creates a subscription with a filter reference, then modifies the referenced
 * filter and verifies that a subscription-modified notification is received.
 */
static void
test_filter_ref_xpath_modify(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    int ret;

    TLOG_INF("Testing modification of referenced XPath filter...");

    setup_sub_filter_ref(st->sess, st->udp_port, 72, "NETCONF", "modifiable-filter",
            "/ietf-netconf-notifications:netconf-config-change");

    /* drain subscription-started notification */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Modifying the referenced filter...");

    /* modify the referenced filter */
    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='modifiable-filter']/stream-xpath-filter");
    ret = sr_set_item_str(st->sess, path, "/ietf-netconf-notifications:*", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-modified notification...");

    /* should receive subscription-modified notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received subscription-modified notification after filter modification");

    lyd_free_all(notif);

    delete_stream_filter(st->sess, "modifiable-filter");
    cleanup_sub(st->sess, 72);
}

/**
 * @brief Test: Modifying a referenced subtree filter triggers subscription-modified.
 *
 * Creates a subscription with a subtree filter reference, then modifies the
 * referenced filter and verifies that a subscription-modified notification is received.
 */
static void
test_filter_ref_subtree_modify(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    sr_val_t val;
    int ret;

    /* initial subtree filter */
    const char *subtree_filter1 =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\"/>";

    /* modified subtree filter - more restrictive */
    const char *subtree_filter2 =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    TLOG_INF("Testing modification of referenced subtree filter...");

    /* create receiver instance */
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a named subtree filter */
    ret = create_subtree_stream_filter(st->sess, "modifiable-subtree-filter", subtree_filter1);
    assert_int_equal(ret, SR_ERR_OK);

    /* create subscription referencing the filter by name */
    ret = create_subscription_filter_ref(st->sess, 73, "NETCONF", "modifiable-subtree-filter", "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* drain subscription-started notification */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Modifying the referenced subtree filter...");

    /* modify the referenced filter */
    memset(&val, 0, sizeof(val));
    val.type = SR_ANYDATA_T;
    val.data.anydata_val = (char *)subtree_filter2;

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='modifiable-subtree-filter']/stream-subtree-filter");
    ret = sr_set_item(st->sess, path, &val, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-modified notification...");

    /* should receive subscription-modified notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received subscription-modified notification after subtree filter modification");

    lyd_free_all(notif);

    delete_stream_filter(st->sess, "modifiable-subtree-filter");
    cleanup_sub(st->sess, 73);
}

/**
 * @brief Test: Multiple subscriptions referencing the same filter.
 *
 * Creates two subscriptions referencing the same named filter, then modifies
 * the filter and verifies that both subscriptions receive subscription-modified.
 */
static void
test_filter_ref_multiple_subs(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    int ret, modified_count;

    TLOG_INF("Testing multiple subscriptions referencing the same filter...");

    /* create receiver instance */
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a named xpath filter */
    ret = create_xpath_stream_filter(st->sess, "shared-filter",
            "/ietf-netconf-notifications:netconf-config-change");
    assert_int_equal(ret, SR_ERR_OK);

    /* create two subscriptions referencing the same filter */
    ret = create_subscription_filter_ref(st->sess, 74, "NETCONF", "shared-filter", "test-recv");
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_subscription_filter_ref(st->sess, 75, "NETCONF", "shared-filter", "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* drain subscription-started notifications */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Modifying the shared filter...");

    /* modify the shared filter */
    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:filters/stream-filter[name='shared-filter']/stream-xpath-filter");
    ret = sr_set_item_str(st->sess, path, "/ietf-netconf-notifications:*", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-modified notifications from both subscriptions...");

    /* should receive two subscription-modified notifications */
    modified_count = 0;
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL);
    if ((ret == 0) && notif) {
        modified_count++;
        lyd_free_all(notif);
        notif = NULL;
    }

    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL);
    if ((ret == 0) && notif) {
        modified_count++;
        lyd_free_all(notif);
        notif = NULL;
    }

    assert_int_equal(modified_count, 2);
    TLOG_INF("Received %d subscription-modified notifications - both subscriptions were notified", modified_count);

    /* cleanup */
    delete_subscription(st->sess, 74);
    delete_subscription(st->sess, 75);
    delete_stream_filter(st->sess, "shared-filter");
    delete_receiver_instance(st->sess, "test-recv");
    sr_apply_changes(st->sess, 0);
}

/**
 * @brief Test: XPath filter reference that does not match notifications.
 *
 * Creates a subscription with an XPath filter reference that filters out
 * notifications and verifies that non-matching notifications are not received.
 */
static void
test_filter_ref_xpath_nomatch(void **state)
{
    struct state *st = *state;
    uint64_t excluded_baseline;
    int ret;

    TLOG_INF("Testing XPath filter reference that should not match...");

    setup_sub_filter_ref(st->sess, st->udp_port, 76, "NETCONF", "nomatch-filter",
            "/ietf-netconf-notifications:netconf-session-start");

    /* drain subscription-started notification */
    drain_notifications(st->udp_sockfd);

    /* read baseline excluded-event-records counter */
    ret = get_oper_counter(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='76']"
            "/receivers/receiver[name='recv1']/excluded-event-records", &excluded_baseline);
    assert_int_equal(ret, 0);

    TLOG_INF("Making configuration change to trigger notification...");

    /* make a configuration change - this generates netconf-config-change, not session-start */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "34", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for excluded-event-records to increment (notification was filtered)...");

    /* wait for excluded-event-records to increment, proving the notification was filtered */
    ret = wait_for_excluded_records_increment(st->sess, 76, excluded_baseline, COUNTER_WAIT_MS);
    assert_int_equal(ret, 0);

    TLOG_INF("excluded-event-records incremented - XPath filter reference correctly filtered out the notification");

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    delete_stream_filter(st->sess, "nomatch-filter");
    cleanup_sub(st->sess, 76);
}

/**
 * @brief Test: Retrieve all supported operational data leaves for a subscription.
 *
 * Uses SR_DS_OPERATIONAL and sr_get_data() to read all leaves provided by
 * sysrepo-notifd operational callbacks for configured subscriptions.
 */
static void
test_oper_data_get_all_supported(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    struct lyd_node *node = NULL;
    sr_data_t *data = NULL;
    LY_ERR lyrc;
    int ret;

    TLOG_INF("Testing retrieval of all supported operational leaves...");

    setup_sub(st->sess, st->udp_port, 90, "NETCONF", NULL);

    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Retrieving operational data for the subscription...");

    ret = sr_session_switch_ds(st->sess, SR_DS_OPERATIONAL);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_get_data(st->sess, "/ietf-subscribed-notifications:subscriptions/subscription[id='90']", 0, 0, 0, &data);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(data);
    assert_non_null(data->tree);

    /* check for presence of all supported leaves */
    lyrc = lyd_find_path(data->tree,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='90']/replay-start-time", 0, &node);
    if (lyrc == LY_SUCCESS) {
        /* some notifications may remain in the replay log at the time we read operational data */
        assert_non_null(node);
        assert_non_null(lyd_get_value(node));
    } else {
        assert_int_equal(lyrc, LY_EINCOMPLETE);
    }

    lyrc = lyd_find_path(data->tree,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='90']/configured-subscription-state", 0, &node);
    assert_int_equal(lyrc, LY_SUCCESS);
    assert_non_null(node);
    assert_non_null(lyd_get_value(node));
    assert_string_equal(lyd_get_value(node), "valid");

    lyrc = lyd_find_path(data->tree,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='90']/receivers/receiver[name='recv1']/sent-event-records", 0,
            &node);
    assert_int_equal(lyrc, LY_SUCCESS);
    assert_non_null(node);
    assert_non_null(lyd_get_value(node));
    assert_true(atoi(lyd_get_value(node)) > 0);

    lyrc = lyd_find_path(data->tree,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='90']/receivers/receiver[name='recv1']/excluded-event-records",
            0, &node);
    assert_int_equal(lyrc, LY_SUCCESS);
    assert_non_null(node);
    assert_non_null(lyd_get_value(node));
    assert_int_equal(atoi(lyd_get_value(node)), 0);

    lyrc = lyd_find_path(data->tree,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='90']/receivers/receiver[name='recv1']/state", 0, &node);
    assert_int_equal(lyrc, LY_SUCCESS);
    assert_non_null(node);
    assert_non_null(lyd_get_value(node));
    assert_string_equal(lyd_get_value(node), "active");

    sr_release_data(data);
    data = NULL;

    ret = sr_session_switch_ds(st->sess, SR_DS_RUNNING);
    assert_int_equal(ret, SR_ERR_OK);

    cleanup_sub(st->sess, 90);
}

/**
 * @brief Test: sent-event-records operational value changes after another sent notification.
 */
static void
test_oper_data_sent_event_records_change(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char *val_str = NULL;
    uint64_t sent_before, sent_after;
    int ret;

    TLOG_INF("Testing sent-event-records operational counter change...");

    setup_sub(st->sess, st->udp_port, 91, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    /* drain subscription-started and initial netconf-config-change notifications */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Retrieving initial sent-event-records value...");

    val_str = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/sent-event-records");
    assert_non_null(val_str);
    sent_before = strtoull(val_str, NULL, 10);
    free(val_str);

    TLOG_INF("Making configuration change to trigger notification...");

    ret = sr_set_item_str(st->sess, "/test:test-leaf", "67", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Retrieving sent-event-records value after sending another notification...");

    val_str = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/sent-event-records");
    assert_non_null(val_str);
    sent_after = strtoull(val_str, NULL, 10);
    free(val_str);
    assert_true(sent_after > sent_before);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 91);
}

static void
test_receiver_reset_action(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    sr_val_t *output = NULL;
    char *state_val = NULL;
    size_t output_count = 0;
    int ret;

    TLOG_INF("Testing receiver reset action with backoff reconnect...");

    setup_sub(st->sess, st->udp_port, 91, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    /* drain subscription-started notification */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    /* drain netconf-config-change caused by creating the subscription */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Checking initial state of the receiver...");

    state_val = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/state");
    assert_non_null(state_val);
    assert_string_equal(state_val, "active");
    free(state_val);

    TLOG_INF("Performing receiver reset action...");

    /* perform the receiver reset action */
    ret = sr_rpc_send(st->sess, "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/reset",
            NULL, 0, 0, &output, &output_count);
    assert_int_equal(ret, SR_ERR_OK);
    assert_non_null(output);
    assert_int_equal(output_count, 1);
    sr_free_values(output, output_count);

    TLOG_INF("Receiver reset action performed, checking state of the receiver...");

    state_val = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/state");
    assert_non_null(state_val);
    assert_string_equal(state_val, "connecting");
    free(state_val);

    TLOG_INF("Triggering a notification to cause backoff reconnect...");

    /* make a config change - the daemon should auto-reconnect and deliver the notification */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "104", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-started (from backoff reconnect)...");

    /* first, the daemon reconnects and sends subscription-started - use long timeout for backoff */
    ret = receive_specific_notification_timeout(st->udp_sockfd, st->ly_ctx, LONG_TIMEOUT_MS,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Waiting for netconf-config-change (after reconnect)...");

    /* then, the actual notification is sent */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Checking receiver state after backoff reconnect...");

    state_val = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='91']/receivers/receiver[name='recv1']/state");
    assert_non_null(state_val);
    assert_string_equal(state_val, "active");
    free(state_val);

    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 91);
}

/**
 * @brief Test: Set configured-replay before replay support, then enable replay and verify delivery.
 *
 * Sets configured-replay before sr_set_module_replay_support, expecting
 * subscription-terminated with replay-not-supported. Then enables replay,
 * makes a config change (stored for replay), deletes and re-sets
 * configured-replay, and verifies: replayed netconf-config-change +
 * subscription-modified + live netconf-config-change.
 */
static void
test_configured_replay(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char replay_path[256];
    int ret;
    int got_modified = 0, got_ncc = 0, got_replay_completed = 0;
    time_t deadline;

    memset(replay_path, 0, sizeof(replay_path));

    snprintf(replay_path, sizeof(replay_path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='93']/configured-replay");

    TLOG_INF("Testing configured-replay...");

    setup_sub(st->sess, st->udp_port, 93, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    /* receive subscription-started */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    /* drain the netconf-config-change from creating the subscription */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Setting configured-replay before replay support is enabled, expecting failure...");

    /* set configured-replay BEFORE enabling replay support - should fail */
    ret = sr_set_item_str(st->sess, replay_path, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_UNSUPPORTED);

    TLOG_INF("Enabling replay support...");

    /* enable replay support */
    ret = sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 1);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Making config change to generate notification stored for replay...");

    /* make a config change - generates ncc stored for replay (sub is INVALID, won't receive live) */
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "42", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Re-setting configured-replay...");

    /* set configured-replay again - now replay is supported */
    ret = sr_set_item_str(st->sess, replay_path, NULL, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-modified, replayed ncc, and replay-completed...");

    /* expect: subscription-modified + replayed ncc + replay-completed within a bounded total time */
    got_modified = got_ncc = got_replay_completed = 0;
    deadline = time(NULL) + 15;

    while ((time(NULL) < deadline) && !(got_modified && got_ncc && got_replay_completed)) {
        ret = receive_notification_timeout(st->udp_sockfd, st->ly_ctx, 500, &notif, NULL);
        if (ret == 1) {
            /* short timeout expired, retry within deadline */
            continue;
        }
        assert_int_equal(ret, 0);
        assert_non_null(notif);

        if (!strcmp(notif->schema->name, "subscription-modified")) {
            got_modified = 1;
        } else if (!strcmp(notif->schema->name, "netconf-config-change")) {
            got_ncc = 1;
        } else if (!strcmp(notif->schema->name, "replay-completed")) {
            got_replay_completed = 1;
        }

        lyd_free_all(notif);
        notif = NULL;
    }

    assert_true(got_modified && got_ncc && got_replay_completed);

    if (notif) {
        lyd_free_all(notif);
        notif = NULL;
    }

    /* cleanup */
    sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 0);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    cleanup_sub(st->sess, 93);
}

/**
 * @brief Test: Modify subscription source-address and verify sender source IP changes.
 */
static void
test_source_address_modify(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    char first_source[INET_ADDRSTRLEN];
    char second_source[INET_ADDRSTRLEN];
    char alternate_source[INET_ADDRSTRLEN];
    const char *initial_source = "127.0.0.1";
    int ret;

    memset(first_source, 0, sizeof(first_source));
    memset(second_source, 0, sizeof(second_source));
    memset(alternate_source, 0, sizeof(alternate_source));

    if (!find_alternate_loopback_ipv4(initial_source, alternate_source, sizeof(alternate_source))) {
        skip();
        return;
    }

    TLOG_INF("Testing source-address change from %s to %s", initial_source, alternate_source);

    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    ret = create_subscription(st->sess, 92, "NETCONF", NULL, "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='92']/source-address");
    ret = sr_set_item_str(st->sess, path, initial_source, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = receive_specific_notification_ext(st->udp_sockfd, st->ly_ctx, NOTIF_TIMEOUT_MS,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL,
            first_source, sizeof(first_source));
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    assert_string_equal(first_source, initial_source);
    lyd_free_all(notif);
    notif = NULL;

    /* drain the initial netconf-config-change notification caused by the subscription creation */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Modifying source-address to %s", alternate_source);

    ret = sr_set_item_str(st->sess, path, alternate_source, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* source address modified, so we should receive a subscription-modified notification with the new source IP */
    ret = receive_specific_notification_ext(st->udp_sockfd, st->ly_ctx, NOTIF_TIMEOUT_MS,
            "/ietf-subscribed-notifications:subscription-modified", &notif, NULL,
            second_source, sizeof(second_source));
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    assert_string_equal(second_source, alternate_source);
    lyd_free_all(notif);
    notif = NULL;

    cleanup_sub(st->sess, 92);
}

/**
 * @brief Test: Change receiver instance reference from one receiver to another.
 *
 * Creates a subscription with receiver instance A, then changes the subscription
 * to point to receiver instance B. Verifies the configuration change is applied
 * successfully and that subscription-started and subscription-terminated notifications are sent to the correct receivers.
 */
static void
test_receiver_instance_ref_change(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    char path[512];
    int ret, recv2_sockfd = -1;

    TLOG_INF("Creating first and second receiver instances...");

    /*
     Create two receiver instances
     */
    ret = create_receiver_instance(st->sess, "recv-1", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_receiver_instance(st->sess, "recv-2", "127.0.0.1", st->udp_port + 1);
    assert_int_equal(ret, SR_ERR_OK);

    /* create a socket for the second receiver */
    recv2_sockfd = create_udp_receiver_socket(st->udp_port + 1);
    assert_true(recv2_sockfd >= 0);

    /*
     Create subscription pointing to recv-1
     */
    ret = create_subscription(st->sess, 100, "NETCONF", NULL, "recv-1");
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Created subscription pointing to recv-1");

    /* Drain notifications */
    drain_notifications(st->udp_sockfd);

    TLOG_INF("Changing receiver instance reference from recv-1 to recv-2...");

    /*
     Change subscription to point to recv-2
     */
    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='100']/receivers/receiver[name='recv1']/ietf-subscribed-notif-receivers:receiver-instance-ref");
    ret = sr_set_item_str(st->sess, path, "recv-2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Receiver instance reference changed to recv-2");

    /*
     Receive subscription-terminated
     */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-terminated", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    TLOG_INF("Received subscription-terminated notification");

    lyd_free_all(notif);
    notif = NULL;

    /*
     Receive subscription-started, it will be sent to the new receiver instance (recv-2)
     */
    ret = receive_specific_notification(recv2_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    TLOG_INF("Received subscription-started notification");

    lyd_free_all(notif);
    notif = NULL;

    /*
     Cleanup
     */
    delete_subscription(st->sess, 100);
    delete_receiver_instance(st->sess, "recv-1");
    delete_receiver_instance(st->sess, "recv-2");
    sr_apply_changes(st->sess, 0);
    if (recv2_sockfd >= 0) {
        close(recv2_sockfd);
    }
}

static int
running_with_valgrind(void)
{
    char *ld_preload;

    ld_preload = getenv("LD_PRELOAD");
    if (ld_preload && strstr(ld_preload, "vgpreload")) {
        return 1;
    }
    return 0;
}

/**
 * @brief Test: Stop-time reached triggers subscription-completed and concluded state.
 */
static void
test_stop_time_concluded(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL;
    time_t now;
    char stop_time_str[64];
    char *state_val = NULL;
    char path[512];
    int ret;

    TLOG_INF("Testing stop-time reaching concluded state...");

    /* create receiver instance */
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);

    /* create subscription */
    ret = create_subscription(st->sess, 200, "NETCONF", NULL, "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    /* set stop-time to a few seconds from now */
    now = time(NULL);
    if (running_with_valgrind()) {
        /* Valgrind can cause significant delays, so set a longer stop-time */
        now += 6;
    } else {
        now += 3;
    }
    strftime(stop_time_str, sizeof(stop_time_str), "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='200']/stop-time");
    ret = sr_set_item_str(st->sess, path, stop_time_str, NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* apply all changes */
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for subscription-started notification...");

    /* receive subscription-started */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Waiting for subscription-completed notification (stop-time will expire)...");

    /* wait for subscription-completed after stop-time expires, using a long timeout */
    ret = receive_specific_notification_timeout(st->udp_sockfd, st->ly_ctx, LONG_TIMEOUT_MS,
            "/ietf-subscribed-notifications:subscription-completed", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);

    TLOG_INF("Received subscription-completed notification successfully");

    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Checking operational state is 'concluded'...");

    state_val = get_oper_leaf_str(st->sess,
            "/ietf-subscribed-notifications:subscriptions/subscription[id='200']/configured-subscription-state");
    assert_non_null(state_val);
    assert_string_equal(state_val, "concluded");
    free(state_val);

    cleanup_sub(st->sess, 200);
}

/**
 * @brief Test: notification envelope wraps a config-change notification (JSON).
 */
static void
test_envelope_basic(void **state)
{
    struct state *st = *state;
    struct lyd_node *env = NULL, *notif = NULL, *node = NULL;
    int ret;

    TLOG_INF("Enabling notification envelope...");
    ret = set_envelope_enabled(st->sess, 1);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Creating subscription for netconf-config-change...");
    setup_sub(st->sess, st->udp_port, 100, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    TLOG_INF("Waiting for envelope-wrapped subscription-started...");
    ret = receive_envelope_notification(st->udp_sockfd, st->ly_ctx, &env, &notif);
    assert_int_equal(ret, 0);
    assert_non_null(env);
    assert_non_null(notif);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Making configuration change to trigger notification...");
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "1", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for envelope-wrapped config-change notification...");
    ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &env, &notif);
    assert_int_equal(ret, 0);
    assert_non_null(env);
    assert_non_null(notif);

    /* verify envelope root is the sx:structure "envelope" */
    assert_string_equal(LYD_NAME(env), "envelope");

    /* verify event-time present */
    node = find_envelope_child(env, "event-time");
    assert_non_null(node);

    /* verify inner notification */
    assert_string_equal(notif->schema->name, "netconf-config-change");

    TLOG_INF("Received envelope-wrapped config-change notification successfully");

    /* cleanup */
    lyd_free_all(env);
    lyd_free_all(notif);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_apply_changes(st->sess, 0);
    cleanup_sub(st->sess, 100);
}

/**
 * @brief Test: envelope hostname and sequence-number present and strictly increasing.
 */
static void
test_envelope_hostname_sequence(void **state)
{
    struct state *st = *state;
    struct lyd_node *env = NULL, *notif = NULL, *node = NULL;
    char hostname[256] = {0};
    char val_str[16];
    uint32_t prev_seq = 0, seq;
    int i, ret;

    TLOG_INF("Enabling notification envelope...");
    ret = set_envelope_enabled(st->sess, 1);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Creating subscription for netconf-config-change...");
    setup_sub(st->sess, st->udp_port, 101, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    /* drain envelope-wrapped subscription-started */
    ret = receive_envelope_notification(st->udp_sockfd, st->ly_ctx, &env, &notif);
    assert_int_equal(ret, 0);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    /* get test process hostname for comparison */
    ret = gethostname(hostname, sizeof(hostname) - 1);
    assert_int_equal(ret, 0);

    TLOG_INF("Triggering 5 config-change notifications...");

    for (i = 0; i < 5; i++) {
        snprintf(val_str, sizeof(val_str), "%d", 100 + i);
        ret = sr_set_item_str(st->sess, "/test:test-leaf", val_str, NULL, 0);
        assert_int_equal(ret, SR_ERR_OK);
        ret = sr_apply_changes(st->sess, 0);
        assert_int_equal(ret, SR_ERR_OK);

        ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
                "/ietf-netconf-notifications:netconf-config-change", &env, &notif);
        assert_int_equal(ret, 0);
        assert_non_null(env);
        assert_non_null(notif);

        /* verify hostname matches the test process */
        node = find_envelope_child(env, "hostname");
        assert_non_null(node);
        assert_string_equal(lyd_get_value(node), hostname);

        /* verify sequence-number is strictly increasing */
        node = find_envelope_child(env, "sequence-number");
        assert_non_null(node);
        seq = (uint32_t)strtoul(lyd_get_value(node), NULL, 10);
        assert_true(seq > prev_seq);
        prev_seq = seq;

        lyd_free_all(env);
        env = NULL;
        lyd_free_all(notif);
        notif = NULL;
    }

    TLOG_INF("All 5 envelopes received with strictly increasing sequence numbers");

    /* cleanup */
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_apply_changes(st->sess, 0);
    cleanup_sub(st->sess, 101);
}

/**
 * @brief Test: notification envelope with XML encoding.
 */
static void
test_envelope_xml(void **state)
{
    struct state *st = *state;
    struct lyd_node *env = NULL, *notif = NULL, *node = NULL;
    char path[512];
    int ret;

    TLOG_INF("Enabling notification envelope...");
    ret = set_envelope_enabled(st->sess, 1);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Creating subscription with XML encoding...");
    ret = create_receiver_instance(st->sess, "test-recv", "127.0.0.1", st->udp_port);
    assert_int_equal(ret, SR_ERR_OK);
    ret = create_subscription(st->sess, 102, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change", "test-recv");
    assert_int_equal(ret, SR_ERR_OK);

    /* set encoding to XML */
    snprintf(path, sizeof(path),
            "/ietf-subscribed-notifications:subscriptions/subscription[id='102']/encoding");
    ret = sr_set_item_str(st->sess, path, "ietf-subscribed-notifications:encode-xml", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    /* drain envelope-wrapped subscription-started */
    ret = receive_envelope_notification(st->udp_sockfd, st->ly_ctx, &env, &notif);
    assert_int_equal(ret, 0);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Making configuration change to trigger notification...");
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "2", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for envelope-wrapped XML config-change notification...");
    ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &env, &notif);
    assert_int_equal(ret, 0);
    assert_non_null(env);
    assert_non_null(notif);

    /* verify envelope root is the sx:structure "envelope" */
    assert_string_equal(LYD_NAME(env), "envelope");

    /* verify event-time present */
    node = find_envelope_child(env, "event-time");
    assert_non_null(node);

    TLOG_INF("Received envelope-wrapped XML config-change notification successfully");

    /* cleanup */
    lyd_free_all(env);
    lyd_free_all(notif);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_apply_changes(st->sess, 0);
    cleanup_sub(st->sess, 102);
}

/**
 * @brief Test: toggling enable-notification-envelope switches egress format both ways.
 */
static void
test_envelope_toggle(void **state)
{
    struct state *st = *state;
    struct lyd_node *env = NULL, *notif = NULL;
    int ret;

    TLOG_INF("Creating subscription (envelope disabled)...");
    ret = set_envelope_enabled(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);
    setup_sub(st->sess, st->udp_port, 103, "NETCONF",
            "/ietf-netconf-notifications:netconf-config-change");

    /* drain bare subscription-started */
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    /* --- OFF -> ON --- */
    TLOG_INF("Enabling notification envelope (off -> on)...");
    ret = set_envelope_enabled(st->sess, 1);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for bare subscription-terminated...");
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-terminated", &notif, NULL);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Waiting for envelope-wrapped subscription-started...");
    ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &env, &notif);
    assert_int_equal(ret, 0);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Triggering config-change (should be envelope-wrapped)...");
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "10", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &env, &notif);
    assert_int_equal(ret, 0);
    assert_non_null(env);
    assert_non_null(notif);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    /* --- ON -> OFF --- */
    TLOG_INF("Disabling notification envelope (on -> off)...");
    ret = set_envelope_enabled(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    TLOG_INF("Waiting for envelope-wrapped subscription-terminated...");
    ret = receive_envelope_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-terminated", &env, &notif);
    assert_int_equal(ret, 0);
    lyd_free_all(env);
    env = NULL;
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Waiting for bare subscription-started...");
    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-subscribed-notifications:subscription-started", &notif, NULL);
    assert_int_equal(ret, 0);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Triggering config-change (should be bare)...");
    ret = sr_set_item_str(st->sess, "/test:test-leaf", "11", NULL, 0);
    assert_int_equal(ret, SR_ERR_OK);
    ret = sr_apply_changes(st->sess, 0);
    assert_int_equal(ret, SR_ERR_OK);

    ret = receive_specific_notification(st->udp_sockfd, st->ly_ctx,
            "/ietf-netconf-notifications:netconf-config-change", &notif, NULL);
    assert_int_equal(ret, 0);
    assert_non_null(notif);
    lyd_free_all(notif);
    notif = NULL;

    TLOG_INF("Toggle test completed successfully");

    /* cleanup */
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_apply_changes(st->sess, 0);
    cleanup_sub(st->sess, 103);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_subscription_started, clear_subs_notifs),
        cmocka_unit_test_setup(test_subscription_terminated, clear_subs_notifs),
        cmocka_unit_test_setup(test_subscription_modified, clear_subs_notifs),
        cmocka_unit_test_setup(test_multiple_subscriptions, clear_subs_notifs),
        cmocka_unit_test_setup(test_config_change_notification, clear_subs_notifs),
        cmocka_unit_test_setup(test_udp_notif_header, clear_subs_notifs),
        cmocka_unit_test_setup(test_message_id_increment, clear_subs_notifs),
        cmocka_unit_test_setup(test_xpath_filter_match, clear_subs_notifs),
        cmocka_unit_test_setup(test_xpath_filter_nomatch, clear_subs_notifs),
        cmocka_unit_test_setup(test_xpath_filter_edit_target, clear_subs_notifs),
        cmocka_unit_test_setup(test_subtree_filter_match, clear_subs_notifs),
        cmocka_unit_test_setup(test_subtree_filter_nomatch, clear_subs_notifs),
        cmocka_unit_test_setup(test_subtree_filter_containment, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_xpath_match, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_subtree_match, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_xpath_modify, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_subtree_modify, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_multiple_subs, clear_subs_notifs),
        cmocka_unit_test_setup(test_filter_ref_xpath_nomatch, clear_subs_notifs),
        cmocka_unit_test_setup(test_oper_data_get_all_supported, clear_subs_notifs),
        cmocka_unit_test_setup(test_oper_data_sent_event_records_change, clear_subs_notifs),
        cmocka_unit_test_setup(test_receiver_reset_action, clear_subs_notifs),
        cmocka_unit_test_setup(test_configured_replay, clear_subs_notifs),
        cmocka_unit_test_setup(test_source_address_modify, clear_subs_notifs),
        cmocka_unit_test_setup(test_receiver_instance_ref_change, clear_subs_notifs),
        cmocka_unit_test_setup(test_stop_time_concluded, clear_subs_notifs),
        cmocka_unit_test_setup(test_envelope_basic, clear_subs_notifs),
        cmocka_unit_test_setup(test_envelope_hostname_sequence, clear_subs_notifs),
        cmocka_unit_test_setup(test_envelope_xml, clear_subs_notifs),
        cmocka_unit_test_setup(test_envelope_toggle, clear_subs_notifs),
    };

    test_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
