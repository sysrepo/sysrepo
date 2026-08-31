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
#include <inttypes.h>
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

/** Name of the daemon log file, kept after the tests end to make a failure debuggable */
#define NOTIFD_LOG_NAME "sysrepo-notifd.log"

/** Name of the daemon PID file, used by the ctest cleanup fixture to kill a leftover daemon */
#define NOTIFD_PID_NAME "sysrepo-notifd.pid"

/** Directory containing YANG modules */
#define SCHEMA_DIR TESTS_SRC_DIR "/../modules"

/** Directory containing subscribed_notifications YANG modules */
#define SN_YANG_DIR TESTS_SRC_DIR "/../modules/subscribed_notifications"

/** UDP-Notif protocol constants */
#define UDP_NOTIF_VERSION 1
#define UDP_NOTIF_HDR_SIZE 12
#define UDP_NOTIF_SEG_OPT_SIZE 4
#define UDP_MAX_SIZE 65535

/** UDP-Notif media types */
#define UDP_NOTIF_MT_JSON 1
#define UDP_NOTIF_MT_XML 2

/**
 * @brief Total deadline for a notification that is expected to arrive (milliseconds).
 *
 * The deadline is a total, not a per-attempt timeout, so a successful receive returns as soon as
 * the datagram arrives and a generous value only costs time on the failure path. For the same
 * reason it is not scaled for valgrind, the value is generous enough for both environments.
 */
#define NOTIF_TIMEOUT_MS 50000

/** Return codes of the notification receive functions */
#define NOTIF_RECV_OK      0    /**< notification received */
#define NOTIF_RECV_TIMEOUT 1    /**< deadline expired without a matching notification */
#define NOTIF_RECV_ERR    (-1)  /**< socket, parse or protocol error */

/** Maximum number of messages tracked for reassembly at the same time */
#define MAX_PENDING_MESSAGES 4

/** Maximum number of segments per message */
#define MAX_SEGMENTS_PER_MESSAGE 256

/**
 * @brief Time the socket must stay silent for a negative assertion or a drain (milliseconds).
 *
 * Unlike the deadlines of the waits that expect something, this one is always consumed in full, so
 * it cannot simply be generous and has to be scaled instead, see ::tmo().
 */
#define QUIET_TIMEOUT_MS 300

/** Poll interval for operational data polling (milliseconds) */
#define OPER_POLL_MS 50

/** Total deadline for operational data polling (milliseconds), consumed only until the value appears */
#define OPER_WAIT_MS 25000

/** Multiplier applied to the timeouts that are consumed in full when running under valgrind */
#define VALGRIND_TIMEOUT_MUL 5

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
    int active;                 /**< whether this slot is in use */
} pending_message_t;

/**
 * @brief UDP-Notif segment reassembly context.
 */
struct notif_reasm {
    pending_message_t msgs[MAX_PENDING_MESSAGES];   /**< messages being reassembled */
};

/**
 * @brief Test state structure.
 */
struct state {
    sr_conn_ctx_t *conn;            /**< sysrepo connection */
    sr_session_ctx_t *sess;         /**< running datastore session */
    sr_session_ctx_t *oper_sess;    /**< operational datastore session, avoids switching DS */
    const struct ly_ctx *ly_ctx;    /**< libyang context */
    pid_t notifd_pid;               /**< PID of sysrepo-notifd process */
    int udp_sockfd;                 /**< UDP socket for receiving notifications */
    uint16_t udp_port;              /**< UDP port used for test */
    uint32_t timeout_mul;           /**< multiplier of the fully consumed timeouts, greater than 1 under valgrind */
    sr_subscription_ctx_t *test_subscr; /**< subscription of the running test, freed by its teardown */
    struct notif_reasm reasm;       /**< segment reassembly state */
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
    uint16_t seg_count;         /**< segments the message was reassembled from, 1 if unsegmented */
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
 * Interruptions by a signal are retried against the same deadline.
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
 * The port is always assigned by the system so that several tests, such as the plain and the
 * valgrind variant of this one, may receive notifications at the same time. SO_REUSEADDR is
 * deliberately not set, it would let them silently bind the very same port and steal each
 * other's notifications.
 *
 * @param[out] port Port the socket was bound to.
 * @return Socket FD on success, -1 on error.
 */
static int
create_udp_receiver_socket(uint16_t *port)
{
    int sockfd;
    struct sockaddr_in addr;
    socklen_t addr_len;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) {
        return -1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(0);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

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
 * Handles both unsegmented and segmented UDP-Notif messages. For segmented messages, waits for
 * all segments and reassembles them, without ever re-arming the deadline.
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
receive_notif_deadline(struct state *st, int sockfd, const struct timespec *deadline,
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

    /* the envelope (with eventTime) is returned separately from the inner notification;
     * *notif holds the inner notification for the caller to use and free */
    rc = NOTIF_RECV_OK;

cleanup:
    ly_in_free(in, 0);
    lyd_free_all(envp);
    free(payload_str);
    return rc;
}

/**
 * @brief Check whether the test is running under valgrind.
 *
 * @return 1 if it is, 0 otherwise.
 */
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
 * @brief Scale a timeout that is consumed in full for the current environment.
 *
 * Only for the negative assertions and the drains. Every millisecond of those is spent on every
 * single run, so they cannot be made generous the way ::NOTIF_TIMEOUT_MS is, but the unscaled
 * window would not prove anything under valgrind, where the daemon can be delayed a lot.
 *
 * @param[in] st Test state.
 * @param[in] timeout_ms Base timeout in milliseconds.
 * @return Scaled timeout in milliseconds.
 */
static uint32_t
tmo(const struct state *st, uint32_t timeout_ms)
{
    return timeout_ms * st->timeout_mul;
}

/**
 * @brief Receive one notification, the single receive primitive.
 *
 * Reassembles segmented UDP-Notif messages. If @p path is set, notifications with a different path
 * are discarded and receiving continues until the deadline, which is a total for the whole call.
 *
 * @param[in] st Test state.
 * @param[in] sockfd Socket to receive on.
 * @param[in] path Optional path of the notification to wait for, NULL for any.
 * @param[in] timeout_ms Total deadline in milliseconds, already scaled.
 * @param[out] notif Received notification (caller must free), NULL on timeout.
 * @param[out] header Optional parsed UDP-Notif header (can be NULL).
 * @param[out] src_addr Optional buffer for the source address (can be NULL).
 * @param[in] src_addr_len Size of @p src_addr.
 * @return ::NOTIF_RECV_OK, ::NOTIF_RECV_TIMEOUT or ::NOTIF_RECV_ERR.
 */
static int
recv_notif(struct state *st, int sockfd, const char *path, uint32_t timeout_ms,
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
expect_notif_full(struct state *st, int sockfd, const char *path, udp_notif_header_t *header,
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

/**
 * @brief Assert a notification with @p path arrives; return it, caller must free.
 */
static struct lyd_node *
expect_notif(struct state *st, const char *path)
{
    return expect_notif_full(st, st->udp_sockfd, path, NULL, NULL, 0);
}

/**
 * @brief As expect_notif(), also outputting the UDP-Notif header.
 */
static struct lyd_node *
expect_notif_hdr(struct state *st, const char *path, udp_notif_header_t *header)
{
    return expect_notif_full(st, st->udp_sockfd, path, header, NULL, 0);
}

/**
 * @brief As expect_notif(), on an explicit socket.
 */
static struct lyd_node *
expect_notif_on(struct state *st, int sockfd, const char *path)
{
    return expect_notif_full(st, sockfd, path, NULL, NULL, 0);
}

/**
 * @brief As expect_notif(), also outputting the source address the datagram came from.
 */
static struct lyd_node *
expect_notif_src(struct state *st, const char *path, char *src_addr, size_t src_addr_len)
{
    return expect_notif_full(st, st->udp_sockfd, path, NULL, src_addr, src_addr_len);
}

/**
 * @brief Assert a notification with @p path arrives, then free it.
 */
static void
skip_notif(struct state *st, const char *path)
{
    lyd_free_all(expect_notif(st, path));
}

/**
 * @brief Assert that a notification arrives for each of the given paths, in any order.
 *
 * The daemon does not guarantee the relative order of unrelated notifications, so waiting for them
 * one by one would discard the ones that arrive early.
 *
 * @param[in] st Test state.
 * @param[in] paths NULL-terminated array of paths that must all arrive.
 */
static void
expect_notifs(struct state *st, const char **paths)
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

/**
 * @brief Count the notifications with @p path received until the socket goes quiet.
 *
 * Waits for the first notification of any type and then keeps reading until nothing else arrives,
 * so that a duplicate is detected instead of silently ignored.
 *
 * @param[in] st Test state.
 * @param[in] path Path of the notification to count.
 * @return Number of notifications matching @p path, notifications of other types are discarded.
 */
static uint32_t
count_notifs(struct state *st, const char *path)
{
    struct lyd_node *notif = NULL;
    char *notif_path;
    uint32_t count = 0, timeout_ms = NOTIF_TIMEOUT_MS;

    while (recv_notif(st, st->udp_sockfd, NULL, timeout_ms, &notif, NULL, NULL, 0) == NOTIF_RECV_OK) {
        /* the first notification may take a while, any further one is already waiting */
        timeout_ms = tmo(st, QUIET_TIMEOUT_MS);

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

/**
 * @brief Discard every notification until the socket goes quiet.
 *
 * Only for the per-test reset; inside a test, expect the notification instead of discarding it.
 *
 * @param[in] st Test state.
 */
static void
drain_notifs(struct state *st)
{
    uint8_t buffer[UDP_MAX_SIZE];
    struct timespec deadline;
    ssize_t recv_len;
    int count = 0;

    while (1) {
        deadline_set(tmo(st, QUIET_TIMEOUT_MS), &deadline);
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
 * @brief A YANG module installed for the tests.
 */
struct test_module {
    const char *path;           /**< path to the schema file */
    const char **features;      /**< NULL-terminated enabled features, NULL for none */
};

/** Features needed from ietf-subscribed-notifications */
static const char *sub_ntf_feats[] = {
    "configured", "xpath", "replay", "subtree", "encode-xml", "encode-json", NULL
};

/** Modules installed for the tests, in dependency order */
static const struct test_module test_modules[] = {
    {SN_YANG_DIR "/ietf-interfaces@2018-02-20.yang", NULL},
    {SN_YANG_DIR "/iana-if-type@2014-05-08.yang", NULL},
    {SN_YANG_DIR "/ietf-ip@2018-02-22.yang", NULL},
    {SN_YANG_DIR "/ietf-network-instance@2019-01-21.yang", NULL},
    {SN_YANG_DIR "/ietf-restconf@2017-01-26.yang", NULL},
    {SN_YANG_DIR "/ietf-subscribed-notifications@2019-09-09.yang", sub_ntf_feats},
    {SN_YANG_DIR "/ietf-subscribed-notif-receivers@2024-02-01.yang", NULL},
    {SN_YANG_DIR "/ietf-crypto-types@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/iana-tls-cipher-suite-algs@2024-03-16.yang", NULL},
    {SN_YANG_DIR "/ietf-keystore@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-truststore@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-tls-common@2024-10-10.yang", NULL},
    {SN_YANG_DIR "/ietf-tls-client@2024-03-16.yang", NULL},
    {SN_YANG_DIR "/ietf-udp-client@2025-05-14.yang", NULL},
    {SN_YANG_DIR "/ietf-udp-notif-transport@2025-06-04.yang", NULL},
    {TESTS_SRC_DIR "/files/test.yang", NULL},
    {TESTS_SRC_DIR "/files/notifd-other-publisher.yang", NULL},
};

/**
 * @brief Install the YANG modules needed by the tests.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
install_test_modules(sr_conn_ctx_t *conn)
{
    const char *schema_paths[(sizeof test_modules / sizeof *test_modules) + 1];
    const char **features[sizeof test_modules / sizeof *test_modules];
    uint32_t i;

    for (i = 0; i < sizeof test_modules / sizeof *test_modules; ++i) {
        schema_paths[i] = test_modules[i].path;
        features[i] = test_modules[i].features;
    }
    schema_paths[i] = NULL;

    return sr_install_modules(conn, schema_paths, SN_YANG_DIR, features);
}

/**
 * @brief Remove test YANG modules.
 *
 * Listed explicitly rather than derived from ::test_modules because they must be removed in the
 * reverse dependency order; keep the two in sync.
 *
 * @param[in] conn Sysrepo connection.
 * @return 0 on success, non-zero on failure.
 */
static int
remove_test_modules(sr_conn_ctx_t *conn)
{
    const char *module_names[] = {
        "notifd-other-publisher",
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
    int i, status, ret, logfd;
    char c;
    char run_dir[256], log_path[512], pid_path[512];
    const char *test_name;

    /* keep the files of every test variant separate, the variants may run in parallel */
    test_name = getenv("TEST_NAME");
    if (!test_name) {
        test_name = "test_notifd";
    }
    snprintf(run_dir, sizeof(run_dir), "%s/%s", TESTS_NOTIFD_DATA_DIR, test_name);
    snprintf(log_path, sizeof(log_path), "%s/%s", run_dir, NOTIFD_LOG_NAME);
    snprintf(pid_path, sizeof(pid_path), "%s/%s", run_dir, NOTIFD_PID_NAME);

    /* create the directory for the daemon log and PID file */
    if (mkdir(TESTS_NOTIFD_DATA_DIR, 00755) && (errno != EEXIST)) {
        TLOG_ERR("Failed to create directory \"%s\" (%s)", TESTS_NOTIFD_DATA_DIR, strerror(errno));
        return -1;
    }
    if (mkdir(run_dir, 00755) && (errno != EEXIST)) {
        TLOG_ERR("Failed to create directory \"%s\" (%s)", run_dir, strerror(errno));
        return -1;
    }
    TLOG_INF("sysrepo-notifd log file \"%s\"", log_path);

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

        /* redirect the daemon output into its own log file, it would be interleaved with the test output otherwise */
        logfd = open(log_path, O_WRONLY | O_CREAT | O_TRUNC, 00600);
        if (logfd == -1) {
            goto child_error;
        }
        dup2(logfd, STDOUT_FILENO);
        dup2(logfd, STDERR_FILENO);
        close(logfd);

        execlp(NOTIFD_PATH, "sysrepo-notifd", "-d", "-v", "info", "-s", SCHEMA_DIR, "-p", pid_path, (char *)NULL);

child_error:
        /* setup or exec failed - signal parent by writing to pipe before exiting */
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
        /* setup or exec failed - child wrote error byte before _exit() */
        waitpid(child_pid, &status, 0);
        TLOG_ERR("sysrepo-notifd failed to start with status %d", status);
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

/** Subscription xpath prefix, takes a uint32_t subscription ID */
#define SUB_XP "/ietf-subscribed-notifications:subscriptions/subscription[id='%" PRIu32 "']"

/** Subscription receiver xpath prefix, takes a uint32_t subscription ID and a receiver name */
#define RECV_XP SUB_XP "/receivers/receiver[name='%s']"

/** Subscription receiver xpath without predicates, for subscribing to all of them */
#define ANY_RECV_XP "/ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver"

/** Receiver instance xpath prefix, takes a receiver instance name */
#define INST_XP "/ietf-subscribed-notifications:subscriptions" \
        "/ietf-subscribed-notif-receivers:receiver-instances/receiver-instance[name='%s']"

/** UDP-Notif receiver xpath prefix, takes a receiver instance name */
#define UDP_INST_XP INST_XP "/ietf-udp-notif-transport:udp-notif-receiver"

/** Named stream filter xpath prefix, takes a filter name */
#define FILTER_XP "/ietf-subscribed-notifications:filters/stream-filter[name='%s']"

/** Transport identity of every subscription created by the tests */
#define UDP_TRANSPORT "ietf-udp-notif-transport:udp-notif"

/** Transport identity of a notification publisher other than sysrepo-notifd */
#define OTHER_TRANSPORT "notifd-other-publisher:other-notif"

/** Encoding identities */
#define ENC_XML "ietf-subscribed-notifications:encode-xml"
#define ENC_JSON "ietf-subscribed-notifications:encode-json"

/** Paths of the notifications the tests wait for */
#define SUB_STARTED "/ietf-subscribed-notifications:subscription-started"
#define SUB_MODIFIED "/ietf-subscribed-notifications:subscription-modified"
#define SUB_TERMINATED "/ietf-subscribed-notifications:subscription-terminated"
#define NCC "/ietf-netconf-notifications:netconf-config-change"
#define REPLAY_COMPLETED "/ietf-subscribed-notifications:replay-completed"
#define SUB_COMPLETED "/ietf-subscribed-notifications:subscription-completed"

/** Name of the receiver instance created by setup_sub() */
#define TEST_RECV_INST "test-recv"

/** Name of the subscription receiver created by setup_sub() */
#define TEST_RECV "recv1"

/**
 * @brief Stage a leaf at a printf-formatted xpath on an explicit session, asserting success.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] value Value to set, NULL to create the node without one.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
set_node_on(sr_session_ctx_t *sess, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_set_item_str(sess, xpath, value, NULL, 0), SR_ERR_OK);
}

/**
 * @brief Stage a leaf at a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] value Value to set, NULL to create the node without one.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
set_node(struct state *st, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_set_item_str(st->sess, xpath, value, NULL, 0), SR_ERR_OK);
}

/**
 * @brief Stage a delete of a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
del_node(struct state *st, const char *xpath_fmt, ...)
{
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_delete_item(st->sess, xpath, 0), SR_ERR_OK);
}

/**
 * @brief Stage an anydata node at a printf-formatted xpath, asserting success.
 *
 * @param[in] st Test state.
 * @param[in] xml Anydata XML content.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
set_anydata(struct state *st, const char *xml, const char *xpath_fmt, ...)
{
    char xpath[1024];
    sr_val_t val;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    memset(&val, 0, sizeof val);
    val.type = SR_ANYDATA_T;
    val.data.anydata_val = (char *)xml;

    assert_int_equal(sr_set_item(st->sess, xpath, &val, 0), SR_ERR_OK);
}

/**
 * @brief Stage the leaves given as (relative path, value) pairs below a prefix.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] prefix Already formatted xpath prefix.
 * @param[in] ap NULL-terminated (relative leaf path, value) pairs.
 */
static void
set_leaves(sr_session_ctx_t *sess, const char *prefix, va_list ap)
{
    const char *leaf, *value;
    char xpath[1024];

    while ((leaf = va_arg(ap, const char *))) {
        value = va_arg(ap, const char *);
        snprintf(xpath, sizeof xpath, "%s/%s", prefix, leaf);
        assert_int_equal(sr_set_item_str(sess, xpath, value, NULL, 0), SR_ERR_OK);
    }
}

/**
 * @brief Stage subscription leaves on an explicit session.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs. A NULL value creates the node
 * without one, for empty leaves such as configured-replay.
 */
static void
add_sub_on(sr_session_ctx_t *sess, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);

    va_start(ap, sub_id);
    set_leaves(sess, prefix, ap);
    va_end(ap);
}

/**
 * @brief Stage subscription leaves.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs.
 */
static void
add_sub(struct state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);
}

/**
 * @brief Stage a udp-notif receiver instance on an explicit session.
 *
 * @param[in] sess Session to stage onto.
 * @param[in] name Receiver instance name.
 * @param[in] port Remote port, the address is always 127.0.0.1.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs below udp-notif-receiver.
 */
static void
add_recv_inst_on(sr_session_ctx_t *sess, const char *name, uint32_t port, ...)
{
    char prefix[512], port_str[16];
    va_list ap;

    snprintf(prefix, sizeof prefix, UDP_INST_XP, name);
    snprintf(port_str, sizeof port_str, "%" PRIu32, port);

    set_node_on(sess, "127.0.0.1", "%s/remote-address", prefix);
    set_node_on(sess, port_str, "%s/remote-port", prefix);

    va_start(ap, port);
    set_leaves(sess, prefix, ap);
    va_end(ap);
}

/**
 * @brief Stage a udp-notif receiver instance.
 *
 * @param[in] st Test state.
 * @param[in] name Receiver instance name.
 * @param[in] port Remote port, the address is always 127.0.0.1.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs below udp-notif-receiver.
 */
static void
add_recv_inst(struct state *st, const char *name, uint32_t port, ...)
{
    char prefix[512], port_str[16];
    va_list ap;

    snprintf(prefix, sizeof prefix, UDP_INST_XP, name);
    snprintf(port_str, sizeof port_str, "%" PRIu32, port);

    set_node(st, "127.0.0.1", "%s/remote-address", prefix);
    set_node(st, port_str, "%s/remote-port", prefix);

    va_start(ap, port);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);
}

/**
 * @brief Stage the receiver-instance-ref binding a subscription receiver to a receiver instance.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] recv_name Subscription receiver name.
 * @param[in] inst_name Receiver instance name to point at.
 */
static void
bind_sub_recv(struct state *st, uint32_t sub_id, const char *recv_name, const char *inst_name)
{
    set_node(st, inst_name, RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref",
            sub_id, recv_name);
}

/**
 * @brief Stage an anydata subtree filter on a subscription.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] xml Subtree filter in XML.
 */
static void
add_sub_subtree_filter(struct state *st, uint32_t sub_id, const char *xml)
{
    set_anydata(st, xml, SUB_XP "/stream-subtree-filter", sub_id);
}

/**
 * @brief Stage a named xpath stream filter.
 *
 * @param[in] st Test state.
 * @param[in] name Filter name.
 * @param[in] xpath XPath filter expression.
 */
static void
add_xpath_filter(struct state *st, const char *name, const char *xpath)
{
    set_node(st, xpath, FILTER_XP "/stream-xpath-filter", name);
}

/**
 * @brief Stage a named subtree stream filter.
 *
 * @param[in] st Test state.
 * @param[in] name Filter name.
 * @param[in] xml Subtree filter in XML.
 */
static void
add_subtree_filter(struct state *st, const char *name, const char *xml)
{
    set_anydata(st, xml, FILTER_XP "/stream-subtree-filter", name);
}

/**
 * @brief Apply the staged changes, asserting success.
 *
 * @param[in] st Test state.
 */
static void
apply(struct state *st)
{
    assert_int_equal(sr_apply_changes(st->sess, 0), SR_ERR_OK);
}

/**
 * @brief Stage the common setup: a receiver instance on the test port and a subscription on the
 * NETCONF stream over udp-notif with a single receiver bound to it. Does not apply.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves.
 */
static void
stage_sub(struct state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);
    set_node(st, "NETCONF", "%s/stream", prefix);
    set_node(st, UDP_TRANSPORT, "%s/transport", prefix);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);

    bind_sub_recv(st, sub_id, TEST_RECV, TEST_RECV_INST);
}

/**
 * @brief Stage the common setup with stage_sub() and apply it.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] ... NULL-terminated (relative leaf path, value) pairs of extra subscription leaves.
 */
static void
setup_sub(struct state *st, uint32_t sub_id, ...)
{
    char prefix[512];
    va_list ap;

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    snprintf(prefix, sizeof prefix, SUB_XP, sub_id);
    set_node(st, "NETCONF", "%s/stream", prefix);
    set_node(st, UDP_TRANSPORT, "%s/transport", prefix);

    va_start(ap, sub_id);
    set_leaves(st->sess, prefix, ap);
    va_end(ap);

    bind_sub_recv(st, sub_id, TEST_RECV, TEST_RECV_INST);
    apply(st);
}

/**
 * @brief Assert a descendant leaf of a notification exists and has a value.
 *
 * @param[in] notif Notification to check.
 * @param[in] name Relative path of the leaf.
 * @param[in] value Expected value.
 */
static void
assert_notif_leaf(const struct lyd_node *notif, const char *name, const char *value)
{
    struct lyd_node *node = NULL;

    assert_int_equal(lyd_find_path(notif, name, 0, &node), LY_SUCCESS);
    assert_non_null(node);
    assert_string_equal(lyd_get_value(node), value);
}

/**
 * @brief Assert how many nodes of a data tree match an xpath.
 *
 * @param[in] tree Data tree to search.
 * @param[in] count Expected number of matches.
 * @param[in] xpath_fmt Printf format of the xpath.
 * @param[in] ... Format arguments.
 */
static void
assert_node_count(const struct lyd_node *tree, uint32_t count, const char *xpath_fmt, ...)
{
    struct ly_set *set = NULL;
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(lyd_find_xpath(tree, xpath, &set), LY_SUCCESS);
    if (set->count != count) {
        TLOG_ERR("Expected %" PRIu32 " nodes matching \"%s\", found %" PRIu32, count, xpath, set->count);
    }
    assert_int_equal(set->count, count);
    ly_set_free(set, NULL);
}

/**
 * @brief Assert a descendant leaf of a notification is absent.
 *
 * @param[in] notif Notification to check.
 * @param[in] name Relative path of the leaf.
 */
static void
assert_no_notif_leaf(const struct lyd_node *notif, const char *name)
{
    struct lyd_node *node = NULL;

    assert_int_equal(lyd_find_path(notif, name, 0, &node), LY_ENOTFOUND);
}

/**
 * @brief Read a leaf from the operational datastore without asserting.
 *
 * @param[in] st Test state.
 * @param[out] value Leaf value, caller must free. Untouched if the leaf is absent.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return 0 on success, -1 if the leaf could not be read.
 */
static int
try_oper(struct state *st, char **value, const char *xpath_fmt, ...)
{
    sr_data_t *data = NULL;
    struct lyd_node *node = NULL;
    char xpath[1024];
    va_list ap;
    int rc = -1;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (sr_get_data(st->oper_sess, xpath, 0, 0, 0, &data) || !data || !data->tree) {
        goto cleanup;
    }
    if (lyd_find_path(data->tree, xpath, 0, &node) || !node) {
        goto cleanup;
    }

    *value = strdup(lyd_get_value(node));
    assert_non_null(*value);
    rc = 0;

cleanup:
    sr_release_data(data);
    return rc;
}

/**
 * @brief Read a leaf from the operational datastore, asserting it exists.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return Leaf value, caller must free.
 */
static char *
get_oper(struct state *st, const char *xpath_fmt, ...)
{
    char xpath[1024], *value = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (try_oper(st, &value, "%s", xpath)) {
        TLOG_ERR("Failed to read operational leaf \"%s\"", xpath);
        fail();
    }

    return value;
}

/**
 * @brief Read a leaf from the operational datastore and assert its value.
 *
 * @param[in] st Test state.
 * @param[in] value Expected value. Given before the format because the format must come last.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 */
static void
assert_oper(struct state *st, const char *value, const char *xpath_fmt, ...)
{
    char xpath[1024], *read = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    read = get_oper(st, "%s", xpath);
    assert_string_equal(read, value);
    free(read);
}

/**
 * @brief Read a uint64 leaf from the operational datastore without asserting.
 *
 * @param[in] st Test state.
 * @param[out] value Parsed value.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 * @return 0 on success, -1 if the leaf could not be read.
 */
static int
try_oper_u64(struct state *st, uint64_t *value, const char *xpath_fmt, ...)
{
    char xpath[1024], *str = NULL;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    if (try_oper(st, &str, "%s", xpath)) {
        return -1;
    }

    *value = strtoull(str, NULL, 10);
    free(str);
    return 0;
}

/**
 * @brief Poll a uint64 operational leaf until it exceeds a baseline, asserting that it does.
 *
 * Used instead of waiting for a socket timeout to prove that a notification was filtered.
 *
 * @param[in] st Test state.
 * @param[in] baseline Value the leaf must exceed.
 * @param[in] xpath_fmt Printf format of the leaf xpath.
 * @param[in] ... Format arguments.
 */
static void
wait_oper_above(struct state *st, uint64_t baseline, const char *xpath_fmt, ...)
{
    char xpath[1024];
    uint64_t current;
    uint32_t elapsed_ms = 0;
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    while (elapsed_ms < OPER_WAIT_MS) {
        usleep(OPER_POLL_MS * 1000);
        elapsed_ms += OPER_POLL_MS;

        if (!try_oper_u64(st, &current, "%s", xpath) && (current > baseline)) {
            return;
        }
    }

    TLOG_ERR("Operational leaf \"%s\" did not rise above %" PRIu64, xpath, baseline);
    fail();
}

/**
 * @brief Read a whole operational subtree in one get, asserting success.
 *
 * Unlike get_oper(), this returns the tree so that several assertions can be made about a single
 * get; a test proving that getting the whole subtree works must not fall back to one get per leaf.
 *
 * @param[in] st Test state.
 * @param[in] xpath_fmt Printf format of the subtree xpath.
 * @param[in] ... Format arguments.
 * @return Retrieved data, caller must release.
 */
static sr_data_t *
get_oper_tree(struct state *st, const char *xpath_fmt, ...)
{
    sr_data_t *data = NULL;
    char xpath[1024];
    va_list ap;

    va_start(ap, xpath_fmt);
    vsnprintf(xpath, sizeof xpath, xpath_fmt, ap);
    va_end(ap);

    assert_int_equal(sr_get_data(st->oper_sess, xpath, 0, 0, 0, &data), SR_ERR_OK);
    assert_non_null(data);
    assert_non_null(data->tree);

    return data;
}

/**
 * @brief Invoke the reset action of a subscription receiver, asserting it is answered.
 *
 * @param[in] st Test state.
 * @param[in] sub_id Subscription ID.
 * @param[in] recv_name Receiver name.
 */
static void
send_reset(struct state *st, uint32_t sub_id, const char *recv_name)
{
    sr_val_t *output = NULL;
    size_t output_count = 0;
    char xpath[1024];

    snprintf(xpath, sizeof xpath, RECV_XP "/reset", sub_id, recv_name);
    assert_int_equal(sr_rpc_send(st->sess, xpath, NULL, 0, 0, &output, &output_count), SR_ERR_OK);
    assert_non_null(output);
    assert_int_equal(output_count, 1);
    sr_free_values(output, output_count);
}

/**
 * @brief Wait until the daemon reports no configured subscriptions left.
 *
 * @param[in] st Test state.
 */
static void
wait_no_subs(struct state *st)
{
    sr_data_t *data = NULL;
    uint32_t elapsed_ms = 0;
    int empty = 0;

    while (elapsed_ms < OPER_WAIT_MS) {
        if (!sr_get_data(st->oper_sess, "/ietf-subscribed-notifications:subscriptions/subscription",
                0, 0, 0, &data)) {
            empty = !data || !data->tree;
            sr_release_data(data);
            data = NULL;
            if (empty) {
                return;
            }
        }

        usleep(OPER_POLL_MS * 1000);
        elapsed_ms += OPER_POLL_MS;
    }

    TLOG_WRN("Subscriptions still present after the teardown wait");
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
    st->udp_sockfd = -1;
    st->timeout_mul = running_with_valgrind() ? VALGRIND_TIMEOUT_MUL : 1;

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

    /* start the running and operational sessions */
    rc = sr_session_start(st->conn, SR_DS_RUNNING, &st->sess);
    if (rc) {
        TLOG_ERR("sr_session_start failed: %s", sr_strerror(rc));
        return 1;
    }
    rc = sr_session_start(st->conn, SR_DS_OPERATIONAL, &st->oper_sess);
    if (rc) {
        TLOG_ERR("sr_session_start failed: %s", sr_strerror(rc));
        return 1;
    }

    /* create UDP receiver socket on a free port assigned by the system */
    st->udp_sockfd = create_udp_receiver_socket(&st->udp_port);
    if (st->udp_sockfd < 0) {
        TLOG_ERR("Failed to create UDP socket");
        return 1;
    }
    TLOG_INF("Receiving notifications on port %" PRIu16, st->udp_port);

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
        free_pending_message(&st->reasm.msgs[i]);
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
 * @brief Teardown: drop the subscription a test created.
 *
 * Runs even if the test failed on an assertion. test_reset() only clears the datastore, so a
 * subscription owned by the test process would otherwise survive into the next test.
 */
static int
unsubscribe_test_subscr(void **state)
{
    struct state *st = *state;

    sr_unsubscribe(st->test_subscr);
    st->test_subscr = NULL;
    return 0;
}

/**
 * @brief Reset the datastore and the socket before each test.
 *
 * Deletes all subscriptions, receiver instances, named filters and test data, waits until the
 * daemon has actually torn the subscriptions down, and only then discards the notifications that
 * caused. Draining before the daemon is done would leave them for the next test to trip over.
 */
static int
test_reset(void **state)
{
    struct state *st = *state;

    sr_delete_item(st->sess, "/ietf-subscribed-notifications:subscriptions", 0);
    sr_delete_item(st->sess, "/ietf-subscribed-notifications:filters", 0);
    sr_delete_item(st->sess, "/test:test-leaf", 0);
    sr_delete_item(st->sess, "/test:cont", 0);
    sr_apply_changes(st->sess, 0);

    wait_no_subs(st);
    drain_notifs(st);
    return 0;
}

/* ========== TESTS ========== */

/**
 * @brief Test: Create subscription and receive subscription-started notification.
 */
static void
test_subscription_started(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 1, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);
    assert_string_equal(notif->schema->name, "subscription-started");

    /* verify header fields */
    assert_int_equal(header.version, UDP_NOTIF_VERSION);
    assert_int_equal(header.s_flag, 0);
    assert_true((header.media_type == UDP_NOTIF_MT_JSON) || (header.media_type == UDP_NOTIF_MT_XML));

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification contains all required fields.
 *
 * Creates a subscription with stream, transport, encoding, purpose, and
 * stream-xpath-filter, then verifies each field is present in the
 * subscription-started notification.
 */
static void
test_subscription_started_fields(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;

    setup_sub(st, 100,
            "stream-xpath-filter", "/ietf-netconf-notifications:*",
            "encoding", ENC_XML,
            "purpose", "test-purpose", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "id", "100");
    assert_notif_leaf(notif, "stream", "NETCONF");
    assert_notif_leaf(notif, "transport", UDP_TRANSPORT);
    assert_notif_leaf(notif, "encoding", ENC_XML);
    assert_notif_leaf(notif, "purpose", "test-purpose");
    assert_notif_leaf(notif, "stream-xpath-filter", "/ietf-netconf-notifications:*");

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification with stream-filter-name.
 *
 * Creates a subscription that references a named stream filter, then verifies
 * the stream-filter-name field is present in the notification (instead of
 * stream-xpath-filter).
 */
static void
test_subscription_started_filter_ref(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;

    add_xpath_filter(st, "field-test-filter", "/ietf-netconf-notifications:*");
    setup_sub(st, 101, "stream-filter-name", "field-test-filter", NULL);

    notif = expect_notif(st, SUB_STARTED);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "stream-filter-name", "field-test-filter");

    /* the choice is by-reference, so the inline filter must not be reported */
    assert_no_notif_leaf(notif, "stream-xpath-filter");

    lyd_free_all(notif);
}

/**
 * @brief Test: Verify subscription-started notification with JSON encoding.
 *
 * Creates a subscription with encoding set to encode-json, then verifies the
 * media type is JSON and the notification is parsed correctly through the
 * RFC 8040 Section 6.4 JSON envelope.
 */
static void
test_subscription_started_json(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 102,
            "stream-xpath-filter", "/ietf-netconf-notifications:*",
            "encoding", ENC_JSON,
            "purpose", "test-purpose-json", NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_JSON);
    assert_string_equal(notif->schema->name, "subscription-started");

    assert_notif_leaf(notif, "id", "102");
    assert_notif_leaf(notif, "stream", "NETCONF");
    assert_notif_leaf(notif, "transport", UDP_TRANSPORT);
    assert_notif_leaf(notif, "encoding", ENC_JSON);
    assert_notif_leaf(notif, "purpose", "test-purpose-json");
    assert_notif_leaf(notif, "stream-xpath-filter", "/ietf-netconf-notifications:*");

    lyd_free_all(notif);
}

/**
 * @brief Test: Delete subscription and receive subscription-terminated notification.
 */
static void
test_subscription_terminated(void **state)
{
    struct state *st = *state;

    setup_sub(st, 2, NULL);
    skip_notif(st, SUB_STARTED);

    del_node(st, SUB_XP, 2);
    apply(st);

    skip_notif(st, SUB_TERMINATED);
}

/**
 * @brief Test: Modify subscription filter and receive subscription-modified notification.
 */
static void
test_subscription_modified(void **state)
{
    struct state *st = *state;

    setup_sub(st, 3, "stream-xpath-filter", "/ietf-netconf-notifications:*", NULL);

    /* modify the filter */
    set_node(st, "/ietf-netconf-notifications:netconf-config-change", SUB_XP "/stream-xpath-filter", 3);
    apply(st);

    skip_notif(st, SUB_MODIFIED);
}

/**
 * @brief Test: Multiple subscriptions to the same receiver.
 */
static void
test_multiple_subscriptions(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif = NULL, *node = NULL;
    uint32_t id, timeout_ms = NOTIF_TIMEOUT_MS;
    int i, started_count = 0, seen[3] = {0};

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);

    /* create 3 subscriptions; the filter keeps out the netconf-config-change that applying this
     * very change produces, the subscription state change notifications are sent regardless of it */
    for (i = 1; i <= 3; i++) {
        add_sub(st, 10 + i, "stream", "NETCONF", "transport", UDP_TRANSPORT,
                "stream-xpath-filter", "/ietf-subscribed-notifications:*", NULL);
        bind_sub_recv(st, 10 + i, TEST_RECV, TEST_RECV_INST);
    }
    apply(st);

    /* read until the socket goes quiet, so that an unexpected extra notification fails the test
     * instead of being left behind for the next one */
    while (recv_notif(st, st->udp_sockfd, NULL, timeout_ms, &notif, NULL, NULL, 0) == NOTIF_RECV_OK) {
        /* the first notification may take a while, any further one is already waiting */
        timeout_ms = tmo(st, QUIET_TIMEOUT_MS);

        assert_string_equal(notif->schema->name, "subscription-started");

        /* every subscription must report started exactly once */
        assert_int_equal(lyd_find_path(notif, "id", 0, &node), LY_SUCCESS);
        id = strtoul(lyd_get_value(node), NULL, 10);
        assert_true((id >= 11) && (id <= 13));
        assert_int_equal(seen[id - 11], 0);
        seen[id - 11] = 1;
        ++started_count;

        lyd_free_all(notif);
        notif = NULL;
    }

    assert_int_equal(started_count, 3);
}

/**
 * @brief Test: netconf-config-change notification through configured subscription.
 */
static void
test_config_change_notification(void **state)
{
    struct state *st = *state;

    setup_sub(st, 20, "stream-xpath-filter", NCC, NULL);

    /* make a configuration change */
    set_node(st, "67", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: UDP-Notif header validation.
 */
static void
test_udp_notif_header(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 30, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header);

    assert_int_equal(header.version, UDP_NOTIF_VERSION);

    /* standard space */
    assert_int_equal(header.s_flag, 0);
    assert_true((header.media_type == UDP_NOTIF_MT_JSON) || (header.media_type == UDP_NOTIF_MT_XML));

    /* no options */
    assert_int_equal(header.header_len, UDP_NOTIF_HDR_SIZE);
    assert_true(header.message_len > UDP_NOTIF_HDR_SIZE);
    assert_true(header.publisher_id > 0);
    assert_true(header.message_id > 0);

    lyd_free_all(notif);
}

/**
 * @brief Test: Message ID incrementing.
 */
static void
test_message_id_increment(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header1, header2;

    setup_sub(st, 40, NULL);

    notif = expect_notif_hdr(st, SUB_STARTED, &header1);
    lyd_free_all(notif);

    /* delete the subscription to generate another notification */
    del_node(st, SUB_XP, 40);
    apply(st);

    notif = expect_notif_hdr(st, SUB_TERMINATED, &header2);
    lyd_free_all(notif);

    assert_true(header2.message_id > header1.message_id);
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

    setup_sub(st, 50, "stream-xpath-filter", NCC, NULL);

    set_node(st, "42", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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
    uint64_t baseline;

    setup_sub(st, 51, "stream-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='startup']", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 51, TEST_RECV), 0);

    /* make a configuration change to running datastore */
    set_node(st, "55", "/test:test-leaf");
    apply(st);

    /* the counter incrementing proves the daemon filtered the notification out */
    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 51, TEST_RECV);
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
    uint64_t baseline;

    setup_sub(st, 52, "stream-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[edit/target=\"/test:test-leaf\"]", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 52, TEST_RECV), 0);

    /* change a different target, this must not match the filter */
    set_node(st, "67", "/test:cont/dflt-leaf");
    apply(st);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 52, TEST_RECV);

    /* change the target the filter selects, this must match */
    set_node(st, "77", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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

    /*
     * subtree filter that matches netconf-config-change notifications
     * an empty element means "select this notification type"
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\"/>";

    stage_sub(st, 60, NULL);
    add_sub_subtree_filter(st, 60, subtree_filter);
    apply(st);

    set_node(st, "88", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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
    uint64_t baseline;

    /*
     * subtree filter that matches only netconf-config-change with datastore=startup
     * we're changing running, so this should NOT match
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>startup</datastore>"
            "</netconf-config-change>";

    stage_sub(st, 61, NULL);
    add_sub_subtree_filter(st, 61, subtree_filter);
    apply(st);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 61, TEST_RECV), 0);

    set_node(st, "99", "/test:test-leaf");
    apply(st);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 61, TEST_RECV);
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
    uint64_t baseline;

    /* subtree filter that matches netconf-config-change with datastore=running */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    stage_sub(st, 62, NULL);
    add_sub_subtree_filter(st, 62, subtree_filter);
    apply(st);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 62, TEST_RECV), 0);

    /* change the startup datastore, the filter selects running so this must not match */
    assert_int_equal(sr_session_switch_ds(st->sess, SR_DS_STARTUP), SR_ERR_OK);
    set_node(st, "100", "/test:test-leaf");
    apply(st);
    assert_int_equal(sr_session_switch_ds(st->sess, SR_DS_RUNNING), SR_ERR_OK);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 62, TEST_RECV);

    /* change the running datastore, this must match */
    set_node(st, "111", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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

    add_xpath_filter(st, "my-xpath-filter",
            "/ietf-netconf-notifications:netconf-config-change[datastore='running']");
    setup_sub(st, 70, "stream-filter-name", "my-xpath-filter", NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "200", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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

    /*
     * subtree filter that matches netconf-config-change notifications
     * with datastore=running - uses containment node filtering
     */
    const char *subtree_filter =
            "<netconf-config-change xmlns=\"urn:ietf:params:xml:ns:yang:ietf-netconf-notifications\">"
            "<datastore>running</datastore>"
            "</netconf-config-change>";

    add_subtree_filter(st, "my-subtree-filter", subtree_filter);
    setup_sub(st, 71, "stream-filter-name", "my-subtree-filter", NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "201", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
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

    add_xpath_filter(st, "modifiable-filter", NCC);
    setup_sub(st, 72, "stream-filter-name", "modifiable-filter", NULL);
    skip_notif(st, SUB_STARTED);

    /* modify the referenced filter */
    add_xpath_filter(st, "modifiable-filter", "/ietf-netconf-notifications:*");
    apply(st);

    skip_notif(st, SUB_MODIFIED);
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
    apply(st);

    skip_notif(st, SUB_MODIFIED);
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

    add_recv_inst(st, TEST_RECV_INST, st->udp_port, NULL);
    add_xpath_filter(st, "shared-filter", NCC);

    /* create two subscriptions referencing the same filter */
    add_sub(st, 74, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "stream-filter-name", "shared-filter", NULL);
    bind_sub_recv(st, 74, TEST_RECV, TEST_RECV_INST);
    add_sub(st, 75, "stream", "NETCONF", "transport", UDP_TRANSPORT,
            "stream-filter-name", "shared-filter", NULL);
    bind_sub_recv(st, 75, TEST_RECV, TEST_RECV_INST);
    apply(st);

    drain_notifs(st);

    /* modify the shared filter */
    add_xpath_filter(st, "shared-filter", "/ietf-netconf-notifications:*");
    apply(st);

    /* exactly two subscription-modified notifications must arrive, one per subscription; count
     * until the socket goes quiet so that a third one fails the test instead of going unnoticed */
    assert_int_equal(count_notifs(st, SUB_MODIFIED), 2);
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
    uint64_t baseline;

    add_xpath_filter(st, "nomatch-filter", "/ietf-netconf-notifications:netconf-session-start");
    setup_sub(st, 76, "stream-filter-name", "nomatch-filter", NULL);
    skip_notif(st, SUB_STARTED);

    assert_int_equal(try_oper_u64(st, &baseline, RECV_XP "/excluded-event-records", 76, TEST_RECV), 0);

    /* this generates netconf-config-change, not netconf-session-start */
    set_node(st, "34", "/test:test-leaf");
    apply(st);

    wait_oper_above(st, baseline, RECV_XP "/excluded-event-records", 76, TEST_RECV);
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
    char *value = NULL;
    uint64_t sent;

    setup_sub(st, 90, NULL);
    skip_notif(st, SUB_STARTED);

    /* some notifications may remain in the replay log at the time we read operational data, so
     * replay-start-time is optional; when present it must have a value */
    if (!try_oper(st, &value, SUB_XP "/replay-start-time", 90)) {
        assert_non_null(value);
        free(value);
    }

    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 90);
    assert_oper(st, "active", RECV_XP "/state", 90, TEST_RECV);
    assert_oper(st, "0", RECV_XP "/excluded-event-records", 90, TEST_RECV);

    assert_int_equal(try_oper_u64(st, &sent, RECV_XP "/sent-event-records", 90, TEST_RECV), 0);
    assert_true(sent > 0);
}

/**
 * @brief Test: sent-event-records operational value changes after another sent notification.
 */
static void
test_oper_data_sent_event_records_change(void **state)
{
    struct state *st = *state;
    uint64_t sent_before, sent_after;

    setup_sub(st, 91, "stream-xpath-filter", NCC, NULL);

    /* the subscription-started and the netconf-config-change caused by creating the subscription */
    skip_notif(st, SUB_STARTED);
    skip_notif(st, NCC);

    assert_int_equal(try_oper_u64(st, &sent_before, RECV_XP "/sent-event-records", 91, TEST_RECV), 0);

    set_node(st, "67", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);

    assert_int_equal(try_oper_u64(st, &sent_after, RECV_XP "/sent-event-records", 91, TEST_RECV), 0);
    assert_true(sent_after > sent_before);
}

/**
 * @brief Test: Receiver reset action moves the receiver to connecting and it reconnects on backoff.
 */
static void
test_receiver_reset_action(void **state)
{
    struct state *st = *state;
    sr_val_t *output = NULL;
    char path[512];
    size_t output_count = 0;

    setup_sub(st, 91, "stream-xpath-filter", NCC, NULL);

    /* the subscription-started and the netconf-config-change caused by creating the subscription */
    skip_notif(st, SUB_STARTED);
    skip_notif(st, NCC);

    assert_oper(st, "active", RECV_XP "/state", 91, TEST_RECV);

    /* perform the receiver reset action */
    snprintf(path, sizeof path, RECV_XP "/reset", 91, TEST_RECV);
    assert_int_equal(sr_rpc_send(st->sess, path, NULL, 0, 0, &output, &output_count), SR_ERR_OK);
    assert_non_null(output);
    assert_int_equal(output_count, 1);
    sr_free_values(output, output_count);

    assert_oper(st, "connecting", RECV_XP "/state", 91, TEST_RECV);

    /* make a config change, the daemon must auto-reconnect and deliver the notification */
    set_node(st, "104", "/test:test-leaf");
    apply(st);

    /* the daemon reconnects and sends subscription-started first */
    skip_notif(st, SUB_STARTED);
    skip_notif(st, NCC);

    assert_oper(st, "active", RECV_XP "/state", 91, TEST_RECV);
}

/**
 * @brief Test: Set configured-replay before replay support, then enable replay and verify delivery.
 *
 * Sets configured-replay before sr_set_module_replay_support, expecting the change to be rejected.
 * Then enables replay, makes a config change (stored for replay), re-sets configured-replay, and
 * verifies: subscription-modified + replayed netconf-config-change + replay-completed.
 */
static void
test_configured_replay(void **state)
{
    struct state *st = *state;

    setup_sub(st, 93, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);

    /* the netconf-config-change from creating the subscription */
    skip_notif(st, NCC);

    /* set configured-replay before enabling replay support, this must be rejected */
    set_node(st, NULL, SUB_XP "/configured-replay", 93);
    assert_int_equal(sr_apply_changes(st->sess, 0), SR_ERR_UNSUPPORTED);

    assert_int_equal(sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 1), SR_ERR_OK);

    /* make a config change, it is stored for replay (the subscription is invalid and will not
     * receive it live) */
    set_node(st, "42", "/test:test-leaf");
    apply(st);

    /* set configured-replay again, now replay is supported */
    set_node(st, NULL, SUB_XP "/configured-replay", 93);
    apply(st);

    /* the daemon does not order these three relative to each other */
    expect_notifs(st, (const char *[]) {SUB_MODIFIED, NCC, REPLAY_COMPLETED, NULL});
}

/**
 * @brief Teardown: disable the replay support enabled by test_configured_replay.
 */
static int
disable_replay_support(void **state)
{
    struct state *st = *state;

    sr_set_module_replay_support(st->conn, "ietf-netconf-notifications", 0);
    return 0;
}

/**
 * @brief Test: Modify subscription source-address and verify sender source IP changes.
 */
static void
test_source_address_modify(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    char first_source[INET_ADDRSTRLEN] = {0};
    char second_source[INET_ADDRSTRLEN] = {0};
    char alternate_source[INET_ADDRSTRLEN] = {0};
    const char *initial_source = "127.0.0.1";

    if (!find_alternate_loopback_ipv4(initial_source, alternate_source, sizeof alternate_source)) {
        skip();
        return;
    }

    TLOG_INF("Testing source-address change from %s to %s", initial_source, alternate_source);

    setup_sub(st, 92, "source-address", initial_source, NULL);

    notif = expect_notif_src(st, SUB_STARTED, first_source, sizeof first_source);
    assert_string_equal(first_source, initial_source);
    lyd_free_all(notif);

    /* the netconf-config-change caused by creating the subscription */
    skip_notif(st, NCC);

    set_node(st, alternate_source, SUB_XP "/source-address", 92);
    apply(st);

    /* the subscription-modified must come from the new source IP */
    notif = expect_notif_src(st, SUB_MODIFIED, second_source, sizeof second_source);
    assert_string_equal(second_source, alternate_source);
    lyd_free_all(notif);
}

/**
 * @brief Test: Change receiver instance reference from one receiver to another.
 *
 * Creates a subscription with receiver instance A, then changes the subscription to point to
 * receiver instance B. Verifies subscription-terminated goes to the old receiver and
 * subscription-started to the new one.
 */
static void
test_receiver_instance_ref_change(void **state)
{
    struct state *st = *state;
    uint16_t recv2_port = 0;
    int recv2_sockfd;

    /* a socket for the second receiver, its port is assigned by the system */
    recv2_sockfd = create_udp_receiver_socket(&recv2_port);
    assert_true(recv2_sockfd >= 0);

    add_recv_inst(st, "recv-1", st->udp_port, NULL);
    add_recv_inst(st, "recv-2", recv2_port, NULL);

    add_sub(st, 100, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    bind_sub_recv(st, 100, TEST_RECV, "recv-1");
    apply(st);

    drain_notifs(st);

    /* point the subscription at the second receiver instance */
    bind_sub_recv(st, 100, TEST_RECV, "recv-2");
    apply(st);

    /* the old receiver is terminated and the new one started */
    skip_notif(st, SUB_TERMINATED);
    lyd_free_all(expect_notif_on(st, recv2_sockfd, SUB_STARTED));

    close(recv2_sockfd);
}

/**
 * @brief Test: Stop-time reached triggers subscription-completed and concluded state.
 */
static void
test_stop_time_concluded(void **state)
{
    struct state *st = *state;
    char stop_time_str[64];
    time_t now;

    /* stop-time a few seconds from now, scaled because valgrind can delay the daemon a lot */
    now = time(NULL) + (3 * st->timeout_mul);
    strftime(stop_time_str, sizeof stop_time_str, "%Y-%m-%dT%H:%M:%SZ", gmtime(&now));

    setup_sub(st, 200, "stop-time", stop_time_str, NULL);

    skip_notif(st, SUB_STARTED);
    skip_notif(st, SUB_COMPLETED);

    assert_oper(st, "concluded", SUB_XP "/configured-subscription-state", 200);
}

/**
 * @brief Test: Verify that adding and removing receivers of a live subscription keeps the
 * notification dispatch coherent.
 *
 * Adding and removing receivers moves the remaining ones in the receivers array, so the callback
 * data pointer held by the srsn read dispatch must stay valid. Otherwise the dispatch thread
 * accesses freed memory and notifd crashes or wedges, blocking any further configuration change.
 */
static void
test_receiver_add_delete_dispatch(void **state)
{
    struct state *st = *state;
    char recv_name[16], *sub_state;
    int i;

    /* subscription with a single receiver "recv1", only config change notifications */
    setup_sub(st, 210, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    /* each added receiver reallocates the receivers array, moving the already dispatched ones */
    for (i = 2; i <= 4; ++i) {
        snprintf(recv_name, sizeof recv_name, "recv%d", i);
        bind_sub_recv(st, 210, recv_name, TEST_RECV_INST);
        apply(st);
        drain_notifs(st);
    }

    /* deleting a receiver stops its dispatch and moves the last receiver into its place */
    for (i = 1; i <= 3; ++i) {
        snprintf(recv_name, sizeof recv_name, "recv%d", i);
        del_node(st, RECV_XP, 210, recv_name);
        apply(st);
        drain_notifs(st);
    }

    /* notifd must still be alive and serving operational data */
    sub_state = get_oper(st, SUB_XP "/configured-subscription-state", 210);
    free(sub_state);

    /* and it must still process configuration changes and set up new dispatches, so replace the
     * churned subscription with a fresh one and expect it to come up normally */
    del_node(st, SUB_XP, 210);
    apply(st);
    drain_notifs(st);

    setup_sub(st, 211, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
}

/**
 * @brief Test: Verify that deleting one receiver leaves the subscription and its other receivers
 * alone.
 *
 * The deleted receiver is reported as a created/deleted list entry followed by its descendant
 * nodes, which carry no operation of their own. Processing those descendants after the entry itself
 * has been destroyed fails to find the receiver and invalidates the whole subscription, terminating
 * every other receiver with it.
 */
static void
test_receiver_delete_keeps_subscription(void **state)
{
    struct state *st = *state;

    /* subscription with receivers "recv1" and "recv2" */
    setup_sub(st, 220, "stream-xpath-filter", NCC, NULL);
    bind_sub_recv(st, 220, "recv2", TEST_RECV_INST);
    apply(st);

    drain_notifs(st);

    del_node(st, RECV_XP, 220, TEST_RECV);
    apply(st);

    /* only the deleted receiver may be terminated, "recv2" must be left alone */
    assert_int_equal(count_notifs(st, SUB_TERMINATED), 1);

    /* and the subscription itself must still be valid */
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 220);

    /* "recv2" must still receive notifications */
    set_node(st, "220", "/test:test-leaf");
    apply(st);

    skip_notif(st, NCC);
}

/**
 * @brief Test: Verify that restarting the daemon over an existing configuration works.
 *
 * On the "enabled" event the whole configuration is presented as a single created subtree, with
 * only the top-level node carrying the operation. Every subscription and receiver below it
 * therefore looks created without saying so, and processing them in the modify steps as well as in
 * the create ones would set up a second dispatch for every receiver, delivering each notification
 * twice.
 */
static void
test_restart_existing_config(void **state)
{
    struct state *st = *state;

    setup_sub(st, 221, "stream-xpath-filter", NCC, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    stop_notifd(st->notifd_pid);
    st->notifd_pid = 0;
    drain_notifs(st);

    assert_int_equal(start_notifd(&st->notifd_pid), 0);

    /* the subscription must be picked up from the datastore and started again */
    skip_notif(st, SUB_STARTED);

    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 221);

    drain_notifs(st);

    set_node(st, "221", "/test:test-leaf");
    apply(st);

    /* the restarted receiver must be dispatched exactly once */
    assert_int_equal(count_notifs(st, NCC), 1);
}

/**
 * @brief Stage the configuration of another notification publisher.
 *
 * A receiver instance with a transport this daemon does not implement, and two subscriptions using
 * it: one declaring the transport of the other publisher and one with no subscription-level
 * transport at all, which the model allows.
 *
 * @param[in] st Test state.
 */
static void
add_other_publisher_config(struct state *st)
{
    /* the receiver instance xpath is transport-agnostic, only the transport case below it differs */
    set_node(st, "https://[::1]/telemetry",
            INST_XP "/notifd-other-publisher:other-notif-receiver/endpoint", "other-inst");

    add_sub(st, 241, "stream", "NETCONF", "transport", OTHER_TRANSPORT, NULL);
    bind_sub_recv(st, 241, "other-recv", "other-inst");

    /* no "transport" leaf at all */
    add_sub(st, 242, "stream", "NETCONF", NULL);
    bind_sub_recv(st, 242, "other-recv", "other-inst");
}

/**
 * @brief Operational get callback of another notification publisher.
 *
 * Provides the state of its own receivers, the very nodes the daemon provides for its receivers.
 */
static int
other_publisher_state_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;
    (void)private_data;

    if (!parent || !*parent) {
        return SR_ERR_OK;
    }

    /* provide the state of the receivers of the other publisher only */
    if (lyd_find_path(*parent, "name", 0, &node) || strcmp(lyd_get_value(node), "other-recv")) {
        return SR_ERR_OK;
    }
    if (lyd_new_term(*parent, NULL, "state", "suspended", 0, NULL)) {
        return SR_ERR_LY;
    }

    return SR_ERR_OK;
}

/**
 * @brief Reset action callback of another notification publisher.
 */
static int
other_publisher_reset_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *op_path,
        const struct lyd_node *input, sr_event_t event, uint32_t request_id, struct lyd_node *output,
        void *private_data)
{
    struct lyd_node *node;

    (void)session;
    (void)sub_id;
    (void)op_path;
    (void)event;
    (void)request_id;
    (void)private_data;

    /* answer for the receivers of the other publisher only */
    if (lyd_find_path(lyd_parent(input), "name", 0, &node) || strcmp(lyd_get_value(node), "other-recv")) {
        return SR_ERR_OK;
    }
    if (lyd_new_term(output, NULL, "time", "2026-01-01T00:00:00Z", LYD_NEW_VAL_OUTPUT, NULL)) {
        return SR_ERR_LY;
    }

    return SR_ERR_OK;
}

/**
 * @brief Test: Subscriptions of another notification publisher are ignored, not broken.
 *
 * The "subscriptions" subtree is shared by all the notification publishers on the system, so it may
 * contain subscriptions with a transport this daemon does not implement (an HTTP-based telemetry
 * server, for example). The daemon must neither reject their configuration nor provide (or delete)
 * any of their state, while keeping its own subscriptions serviced.
 */
static void
test_other_publisher(void **state)
{
    struct state *st = *state;
    sr_data_t *data;

    /* a subscription serviced by the daemon */
    setup_sub(st, 240, NULL);
    skip_notif(st, SUB_STARTED);
    drain_notifs(st);

    /* neither an unimplemented transport nor a subscription without any transport may be rejected */
    add_other_publisher_config(st);
    apply(st);
    drain_notifs(st);

    /* used to fail as a whole, the daemon answered "Item not found" for receivers it does not
     * service, so read the entire subtree in one get and assert on that single result */
    data = get_oper_tree(st, "/ietf-subscribed-notifications:subscriptions");

    /* the state of our own receiver is provided ... */
    assert_node_count(data->tree, 1, RECV_XP "/state", 240, TEST_RECV);
    assert_node_count(data->tree, 1, SUB_XP "/configured-subscription-state", 240);

    /* ... the state of the other publisher's subscriptions is not, we know nothing about them */
    assert_node_count(data->tree, 0, RECV_XP "/state", 241, "other-recv");
    assert_node_count(data->tree, 0, SUB_XP "/configured-subscription-state", 241);
    assert_node_count(data->tree, 0, RECV_XP "/state", 242, "other-recv");
    assert_node_count(data->tree, 0, SUB_XP "/configured-subscription-state", 242);
    sr_release_data(data);

    /* modifying a foreign subscription must leave the daemon and its own subscription alone */
    set_node(st, "telemetry", SUB_XP "/purpose", 241);
    apply(st);
    drain_notifs(st);
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 240);

    /* the other publisher provides the state of its receivers on the very paths the daemon uses */
    assert_int_equal(sr_oper_get_subscribe(st->sess, "ietf-subscribed-notifications", ANY_RECV_XP "/state",
            other_publisher_state_cb, NULL, SR_SUBSCR_OPER_MERGE, &st->test_subscr), SR_ERR_OK);

    /* the state of both publishers is in the operational data */
    assert_oper(st, "suspended", RECV_XP "/state", 241, "other-recv");
    assert_oper(st, "active", RECV_XP "/state", 240, TEST_RECV);

    /* the daemon could not even subscribe for the operational data without SR_SUBSCR_OPER_MERGE */
    stop_notifd(st->notifd_pid);
    st->notifd_pid = 0;
    drain_notifs(st);
    assert_int_equal(start_notifd(&st->notifd_pid), 0);

    skip_notif(st, SUB_STARTED);
    assert_oper(st, "valid", SUB_XP "/configured-subscription-state", 240);

    /* deleting the foreign configuration must leave our own subscription serviced */
    del_node(st, SUB_XP, 241);
    del_node(st, SUB_XP, 242);
    del_node(st, INST_XP, "other-inst");
    apply(st);
    drain_notifs(st);
    assert_oper(st, "active", RECV_XP "/state", 240, TEST_RECV);

    /* the reset action is subscribed by both publishers, each with its own priority (sysrepo allows
     * a single subscription per priority) and the daemon must keep answering for its own receivers.
     * sysrepo keeps only the reply of the lowest-priority subscriber, so the mandatory "time"
     * output of the other publisher is discarded while this daemon is subscribed with priority 0 */
    assert_int_equal(sr_rpc_subscribe_tree(st->sess, ANY_RECV_XP "/reset", other_publisher_reset_cb,
            NULL, 1, 0, &st->test_subscr), SR_ERR_OK);

    send_reset(st, 240, TEST_RECV);
    assert_oper(st, "connecting", RECV_XP "/state", 240, TEST_RECV);
}

/**
 * @brief Test: Verify that changing the encoding of an existing subscription takes effect on
 * subsequent notifications.
 *
 * Creates a subscription with JSON encoding, triggers a notification and verifies it is received as
 * JSON. Then modifies the encoding to XML, triggers another notification and verifies it is
 * received as XML. This catches a receiver sending in the encoding configured when its dispatch was
 * started instead of the one currently configured for the subscription.
 */
static void
test_encoding_modify(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;

    setup_sub(st, 120, "stream-xpath-filter", NCC, "encoding", ENC_JSON, NULL);
    skip_notif(st, SUB_STARTED);

    set_node(st, "1", "/test:test-leaf");
    apply(st);

    notif = expect_notif_hdr(st, NCC, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_JSON);
    lyd_free_all(notif);

    /* change the encoding to XML */
    set_node(st, ENC_XML, SUB_XP "/encoding", 120);
    apply(st);

    skip_notif(st, SUB_MODIFIED);

    set_node(st, "2", "/test:test-leaf");
    apply(st);

    notif = expect_notif_hdr(st, NCC, &header);
    assert_int_equal(header.media_type, UDP_NOTIF_MT_XML);
    lyd_free_all(notif);
}

/**
 * @brief Test: Configuring CBOR encoding must be rejected (not implemented).
 *
 * Attempts to create a subscription with the encode-cbor identity and verifies that it is rejected,
 * since CBOR serialization is not implemented by the daemon.
 */
static void
test_encoding_cbor_unsupported(void **state)
{
    struct state *st = *state;
    sr_session_ctx_t *tmp_sess = NULL;

    /* use a throwaway session so that the edit left behind by the failing apply is dropped with it
     * instead of being applied on top of by the reset */
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
 * @brief Test: Verify transport default encoding when the encoding leaf is not set.
 *
 * Creates a subscription without setting the encoding leaf, then verifies that the feature-aware
 * transport default encoding is used: the highest-priority encoding whose YANG feature is enabled
 * (XML). The UDP-Notif media type must be XML and the subscription-started notification must carry
 * the encoding leaf set to encode-xml.
 */
static void
test_default_encoding(void **state)
{
    struct state *st = *state;
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
 * @brief Teardown: re-enable the encoding features after test_encoding_feature_disabled.
 *
 * Runs even if the test failed on an assertion, so that subsequent test runs start with both
 * features enabled. Must release the context reference so that sr_enable_module_feature can acquire
 * the write lock it needs.
 */
static int
re_enable_encoding_features(void **state)
{
    struct state *st = *state;
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
 * Disables the encode-json and encode-xml features and verifies that creating a subscription
 * without an explicit encoding fails (there is no usable default). Then re-enables encode-json only
 * and verifies that explicitly configuring encode-xml is rejected (its feature is disabled), and
 * that a subscription without an explicit encoding is created, uses the JSON media type, and
 * carries the encoding leaf set to encode-json (the higher-priority encode-xml is skipped because
 * its feature is disabled).
 *
 * Must be the last test in the suite because it disables YANG features.
 */
static void
test_encoding_feature_disabled(void **state)
{
    struct state *st = *state;
    struct lyd_node *notif;
    udp_notif_header_t header;
    sr_session_ctx_t *tmp_sess = NULL;
    char xpath[512];
    int ret;

    /* release the context reference so the feature changes can acquire the write lock they need to
     * change the libyang context */
    sr_release_context(st->conn);
    st->ly_ctx = NULL;

    assert_int_equal(sr_disable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-json"), SR_ERR_OK);
    assert_int_equal(sr_disable_module_feature(st->conn, "ietf-subscribed-notifications", "encode-xml"), SR_ERR_OK);

    /* re-acquire the context, now with both encoding features disabled */
    st->ly_ctx = sr_acquire_context(st->conn);

    /* use a throwaway session for the failing apply so that any state left by the failed change is
     * dropped with it */
    assert_int_equal(sr_session_start(st->conn, SR_DS_RUNNING, &tmp_sess), SR_ERR_OK);

    add_recv_inst_on(tmp_sess, TEST_RECV_INST, st->udp_port, NULL);
    add_sub_on(tmp_sess, 111, "stream", "NETCONF", "transport", UDP_TRANSPORT, NULL);
    set_node_on(tmp_sess, TEST_RECV_INST,
            RECV_XP "/ietf-subscribed-notif-receivers:receiver-instance-ref", 111, TEST_RECV);

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

    /* an identity disabled by if-feature is refused already when staging the edit if the context
     * has the parsed module data, which is not the case for a printed context, then the edit is
     * created, passes the libyang validation for the same reason, and is rejected only by the
     * change event validation of the daemon */
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
    apply(st);

    /* re-acquire context for the teardown function */
    st->ly_ctx = sr_acquire_context(st->conn);
}

/* MAIN */
int
main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup(test_subscription_started, test_reset),
        cmocka_unit_test_setup(test_subscription_started_fields, test_reset),
        cmocka_unit_test_setup(test_subscription_started_filter_ref, test_reset),
        cmocka_unit_test_setup(test_subscription_started_json, test_reset),
        cmocka_unit_test_setup(test_subscription_terminated, test_reset),
        cmocka_unit_test_setup(test_subscription_modified, test_reset),
        cmocka_unit_test_setup(test_multiple_subscriptions, test_reset),
        cmocka_unit_test_setup(test_config_change_notification, test_reset),
        cmocka_unit_test_setup(test_udp_notif_header, test_reset),
        cmocka_unit_test_setup(test_message_id_increment, test_reset),
        cmocka_unit_test_setup(test_xpath_filter_match, test_reset),
        cmocka_unit_test_setup(test_xpath_filter_nomatch, test_reset),
        cmocka_unit_test_setup(test_xpath_filter_edit_target, test_reset),
        cmocka_unit_test_setup(test_subtree_filter_match, test_reset),
        cmocka_unit_test_setup(test_subtree_filter_nomatch, test_reset),
        cmocka_unit_test_setup(test_subtree_filter_containment, test_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_match, test_reset),
        cmocka_unit_test_setup(test_filter_ref_subtree_match, test_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_modify, test_reset),
        cmocka_unit_test_setup(test_filter_ref_subtree_modify, test_reset),
        cmocka_unit_test_setup(test_filter_ref_multiple_subs, test_reset),
        cmocka_unit_test_setup(test_filter_ref_xpath_nomatch, test_reset),
        cmocka_unit_test_setup(test_oper_data_get_all_supported, test_reset),
        cmocka_unit_test_setup(test_oper_data_sent_event_records_change, test_reset),
        cmocka_unit_test_setup(test_receiver_reset_action, test_reset),
        cmocka_unit_test_setup_teardown(test_configured_replay, test_reset, disable_replay_support),
        cmocka_unit_test_setup(test_source_address_modify, test_reset),
        cmocka_unit_test_setup(test_receiver_instance_ref_change, test_reset),
        cmocka_unit_test_setup(test_receiver_add_delete_dispatch, test_reset),
        cmocka_unit_test_setup(test_receiver_delete_keeps_subscription, test_reset),
        cmocka_unit_test_setup(test_restart_existing_config, test_reset),
        cmocka_unit_test_setup_teardown(test_other_publisher, test_reset, unsubscribe_test_subscr),
        cmocka_unit_test_setup(test_stop_time_concluded, test_reset),
        cmocka_unit_test_setup(test_encoding_cbor_unsupported, test_reset),
        cmocka_unit_test_setup(test_default_encoding, test_reset),
        cmocka_unit_test_setup(test_encoding_modify, test_reset),
        /* test_encoding_feature_disabled must be last: it disables the encoding features */
        cmocka_unit_test_setup_teardown(test_encoding_feature_disabled, test_reset, re_enable_encoding_features),
    };

    setenv("CMOCKA_TEST_ABORT", "1", 1);
    test_init();
    return cmocka_run_group_tests(tests, setup, teardown);
}
