/**
 * @file notifd_udp.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief sysrepo notification daemon UDP transport implementation
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
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"
#include "compat.h"
#include "notifd.h"

#include <libyang/libyang.h>

/** UDP-Notif protocol version */
#define UDP_NOTIF_VERSION 1

/** UDP-Notif fixed header size in bytes (without options) */
#define UDP_NOTIF_HDR_SIZE 12

/** UDP-Notif segmentation option size in bytes */
#define UDP_NOTIF_SEG_OPT_SIZE 4

/** UDP-Notif segmentation option type */
#define UDP_NOTIF_OPT_SEGMENTATION 1

/** S-flag: no segmentation present */
#define UDP_NOTIF_SFLAG_NONE 0

/** S-flag: segmentation present */
#define UDP_NOTIF_SFLAG_SEG  1

/** Default max segment size if not configured (conservative value for typical MTU) */
#define UDP_NOTIF_DEFAULT_MAX_SEGMENT_SIZE 1400

/**
 * @brief UDP notification receiver configuration.
 *
 * Corresponds to /ietf-subscribed-notifications:receiver-instances/receiver-instance/ietf-udp-notif-transport:udp-notif-receiver
 */
typedef struct udp_notif_receiver_s {
    char *remote_address;       /**< destination address (hostname or IP) */
    uint16_t remote_port;       /**< destination UDP port */

    int enable_segmentation;    /**< whether payload segmentation is enabled */
    uint16_t max_segment_size;  /**< maximum segment size in bytes */

    ATOMIC_T message_id;        /**< monotonically increasing message ID, starts at 1 */
    uint32_t publisher_id;      /**< message publisher ID, identifies this publisher instance */
} udp_notif_receiver_t;

/**
 * @brief UDP transport connection context for a notification receiver.
 */
typedef struct {
    int sockfd;     /**< connected UDP socket file descriptor, -1 if not connected */
} udp_conn_ctx_t;

/*
 * ---------------------------------------------------------------------------
 * UDP-Notif protocol helpers
 * ---------------------------------------------------------------------------
 */

/**
 * @brief UDP-Notif media types (MT field values when S-flag is 0).
 */
typedef enum {
    UDP_NOTIF_MT_RESERVED = 0,  /**< reserved, must not be used */
    UDP_NOTIF_MT_JSON = 1,      /**< application/yang-data+json */
    UDP_NOTIF_MT_XML = 2,       /**< application/yang-data+xml */
    UDP_NOTIF_MT_CBOR = 3       /**< application/yang-data+cbor */
} udp_notif_media_type_t;

/**
 * @brief Convert notification encoding to UDP-Notif media type.
 *
 * @param[in] encoding Notification encoding.
 * @return UDP-Notif media type value.
 */
static udp_notif_media_type_t
encoding_to_media_type(notif_encoding_t encoding)
{
    switch (encoding) {
    case NOTIF_ENCODING_XML:
        return UDP_NOTIF_MT_XML;
    case NOTIF_ENCODING_JSON:
        return UDP_NOTIF_MT_JSON;
    case NOTIF_ENCODING_CBOR:
        return UDP_NOTIF_MT_CBOR;
    case NOTIF_ENCODING_UNSET:
    default:
        /* default to JSON if not set */
        return UDP_NOTIF_MT_JSON;
    }
}

/**
 * @brief Build the fixed UDP-Notif message header.
 *
 * Header format (12 bytes):
 *   - Ver (3 bits) + S-flag (1 bit) + MT (4 bits) = 1 byte
 *   - Header Length (8 bits) = 1 byte
 *   - Message Length (16 bits) = 2 bytes
 *   - Message Publisher ID (32 bits) = 4 bytes
 *   - Message ID (32 bits) = 4 bytes
 *
 * @param[out] hdr Buffer to write header to (must be at least UDP_NOTIF_HDR_SIZE bytes).
 * @param[in] media_type Media type (MT field).
 * @param[in] header_len Total header length including options.
 * @param[in] message_len Total message length (header + payload).
 * @param[in] publisher_id Message Publisher ID.
 * @param[in] message_id Message ID.
 */
static void
udp_notif_hdr_build(uint8_t *hdr, udp_notif_media_type_t media_type, uint8_t header_len,
        uint16_t message_len, uint32_t publisher_id, uint32_t message_id)
{
    /* Ver (3 bits) | S-flag (1 bit) | MT (4 bits) */
    hdr[0] = ((UDP_NOTIF_VERSION & 0x07) << 5) | (UDP_NOTIF_SFLAG_NONE << 4) | (media_type & 0x0F);

    /* Header Length */
    hdr[1] = header_len;

    /* Message Length (network byte order) */
    hdr[2] = (message_len >> 8) & 0xFF;
    hdr[3] = message_len & 0xFF;

    /* Message Publisher ID (network byte order) */
    hdr[4] = (publisher_id >> 24) & 0xFF;
    hdr[5] = (publisher_id >> 16) & 0xFF;
    hdr[6] = (publisher_id >> 8) & 0xFF;
    hdr[7] = publisher_id & 0xFF;

    /* Message ID (network byte order) */
    hdr[8] = (message_id >> 24) & 0xFF;
    hdr[9] = (message_id >> 16) & 0xFF;
    hdr[10] = (message_id >> 8) & 0xFF;
    hdr[11] = message_id & 0xFF;
}

/**
 * @brief Build the segmentation option.
 *
 * Option format (4 bytes):
 *   - Type (8 bits) = 1 byte
 *   - Length (8 bits) = 1 byte
 *   - Segment Number (15 bits) + L flag (1 bit) = 2 bytes
 *
 * @param[out] opt Buffer to write option to (must be at least UDP_NOTIF_SEG_OPT_SIZE bytes).
 * @param[in] segment_num Segment number (0-based).
 * @param[in] is_last Whether this is the last segment.
 */
static void
udp_notif_seg_opt_build(uint8_t *opt, uint16_t segment_num, int is_last)
{
    uint16_t seg_field;

    /* Type */
    opt[0] = UDP_NOTIF_OPT_SEGMENTATION;

    /* Length (total TLV length) */
    opt[1] = UDP_NOTIF_SEG_OPT_SIZE;

    /* Segment Number (15 bits) | L flag (1 bit) */
    seg_field = ((segment_num & 0x7FFF) << 1) | (is_last ? 1 : 0);
    opt[2] = (seg_field >> 8) & 0xFF;
    opt[3] = seg_field & 0xFF;
}

/**
 * @brief Encode a notification to the specified format.
 *
 * @param[in] notif Notification data tree.
 * @param[in] encoding Encoding format.
 * @param[out] data Encoded data (caller must free).
 * @param[out] data_len Length of encoded data.
 * @return SR_ERR_OK on success, error code on failure.
 */
static int
notif_encode(const struct lyd_node *notif, notif_encoding_t encoding, char **data, size_t *data_len)
{
    LYD_FORMAT format;
    uint32_t print_flags = LYD_PRINT_SHRINK;

    *data = NULL;
    *data_len = 0;

    switch (encoding) {
    case NOTIF_ENCODING_XML:
        format = LYD_XML;
        break;
    case NOTIF_ENCODING_JSON:
    case NOTIF_ENCODING_UNSET:
        format = LYD_JSON;
        break;
    case NOTIF_ENCODING_CBOR:
        /* TODO: CBOR encoding not yet supported */
        SRNTF_LOG_ERR("CBOR encoding is not yet implemented.");
        return SR_ERR_UNSUPPORTED;
    default:
        SRNTF_LOG_ERR("Unknown encoding type %d.", encoding);
        return SR_ERR_INVAL_ARG;
    }

    if (lyd_print_mem(data, notif, format, print_flags)) {
        SRNTF_LOG_ERR("Failed to encode notification.");
        return SR_ERR_LY;
    }

    *data_len = strlen(*data);
    return SR_ERR_OK;
}

/**
 * @brief Send a single UDP-Notif segment.
 *
 * @param[in] recv Notification receiver.
 * @param[in] buf Buffer containing the complete segment (header + options + payload).
 * @param[in] len Length of buffer.
 * @return SR_ERR_OK on success, error code on failure.
 */
static int
udp_notif_segment_send(notif_receiver_t *recv, const uint8_t *buf, size_t len)
{
    udp_conn_ctx_t *conn;
    ssize_t sent;

    assert(recv && recv->ops && (recv->ops->type == NOTIF_TRANSPORT_TYPE_UDP) && recv->conn_ctx);

    conn = (udp_conn_ctx_t *)recv->conn_ctx;
    assert(conn->sockfd >= 0);

    sent = send(conn->sockfd, buf, len, 0);
    if (sent < 0) {
        SRNTF_LOG_ERR("Failed to send UDP-Notif message to receiver \"%s\": %s.", recv->name, strerror(errno));
        return SR_ERR_SYS;
    }

    if ((size_t)sent != len) {
        SRNTF_LOG_ERR("Incomplete UDP-Notif send to receiver \"%s\": sent %zd of %zu bytes.", recv->name, sent, len);
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
}

/**
 * @brief Send a notification without segmentation.
 *
 * @param[in] recv Notification receiver.
 * @param[in] udp_recv UDP receiver instance.
 * @param[in] media_type Media type for the message.
 * @param[in] payload Encoded notification payload.
 * @param[in] payload_len Length of payload.
 * @param[in] message_id Message ID to use.
 * @return SR_ERR_OK on success, error code on failure.
 */
static int
udp_notif_send_unsegmented(notif_receiver_t *recv, udp_notif_receiver_t *udp_recv, udp_notif_media_type_t media_type,
        const char *payload, size_t payload_len, uint32_t message_id)
{
    int rc;
    uint8_t *buf = NULL;
    size_t buf_len;
    uint8_t header_len = UDP_NOTIF_HDR_SIZE;
    uint16_t message_len;

    buf_len = header_len + payload_len;
    message_len = (uint16_t)buf_len;

    buf = malloc(buf_len);
    CHECK_ERRMEM_RET(buf);

    /* build header */
    udp_notif_hdr_build(buf, media_type, header_len, message_len,
            udp_recv->publisher_id, message_id);

    /* copy payload */
    memcpy(buf + header_len, payload, payload_len);

    /* send */
    rc = udp_notif_segment_send(recv, buf, buf_len);

    free(buf);
    return rc;
}

/**
 * @brief Send a notification with segmentation.
 *
 * @param[in] recv Notification receiver.
 * @param[in] udp_recv UDP receiver instance.
 * @param[in] media_type Media type for the message.
 * @param[in] payload Encoded notification payload.
 * @param[in] payload_len Length of payload.
 * @param[in] message_id Message ID to use.
 * @param[in] max_segment_size Maximum segment size.
 * @return SR_ERR_OK on success, error code on failure.
 */
static int
udp_notif_send_segmented(notif_receiver_t *recv, udp_notif_receiver_t *udp_recv, udp_notif_media_type_t media_type,
        const char *payload, size_t payload_len, uint32_t message_id, uint16_t max_segment_size)
{
    int rc = SR_ERR_OK;
    uint8_t *buf = NULL;
    size_t buf_len;
    uint8_t header_len = UDP_NOTIF_HDR_SIZE + UDP_NOTIF_SEG_OPT_SIZE;
    size_t max_payload_per_segment;
    size_t offset = 0;
    uint16_t segment_num = 0;
    size_t chunk_len;
    int is_last;

    /* calculate max payload per segment */
    if (max_segment_size <= header_len) {
        SRNTF_LOG_ERR("max-segment-size too small to fit header.");
        return SR_ERR_INVAL_ARG;
    }
    max_payload_per_segment = max_segment_size - header_len;

    /* allocate buffer for one segment */
    buf_len = max_segment_size;
    buf = malloc(buf_len);
    CHECK_ERRMEM_RET(buf);

    /* send segments */
    while (offset < payload_len) {
        /* calculate chunk size */
        chunk_len = payload_len - offset;
        if (chunk_len > max_payload_per_segment) {
            chunk_len = max_payload_per_segment;
        }

        is_last = (offset + chunk_len >= payload_len);

        /* build header */
        udp_notif_hdr_build(buf, media_type, header_len,
                (uint16_t)(header_len + chunk_len),
                udp_recv->publisher_id, message_id);

        /* build segmentation option (must be first option) */
        udp_notif_seg_opt_build(buf + UDP_NOTIF_HDR_SIZE, segment_num, is_last);

        /* copy payload chunk */
        memcpy(buf + header_len, payload + offset, chunk_len);

        /* send segment */
        rc = udp_notif_segment_send(recv, buf, header_len + chunk_len);
        if (rc != SR_ERR_OK) {
            goto cleanup;
        }

        offset += chunk_len;
        segment_num++;

        /* check for segment number overflow (15-bit field) */
        if (segment_num > 0x7FFF) {
            SRNTF_LOG_ERR("Message requires too many segments (max 32768).");
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }
    }

cleanup:
    free(buf);
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * UDP socket helpers
 * ---------------------------------------------------------------------------
 */

static int
udp_notif_local_addr_prepare(const char *local_address, struct sockaddr_storage *local_addr,
        socklen_t *local_addr_len)
{
    struct sockaddr_in *addr4;
    struct sockaddr_in6 *addr6;

    if (!local_address || !local_addr || !local_addr_len) {
        return SR_ERR_INVAL_ARG;
    }

    memset(local_addr, 0, sizeof(*local_addr));

    if (inet_pton(AF_INET6, local_address, &((struct sockaddr_in6 *)local_addr)->sin6_addr) == 1) {
        /* IPv6 */
        addr6 = (struct sockaddr_in6 *)local_addr;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons(0);
        *local_addr_len = sizeof(struct sockaddr_in6);
    } else if (inet_pton(AF_INET, local_address, &((struct sockaddr_in *)local_addr)->sin_addr) == 1) {
        /* IPv4 */
        addr4 = (struct sockaddr_in *)local_addr;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons(0);
        *local_addr_len = sizeof(struct sockaddr_in);
    } else {
        SRNTF_LOG_ERR("Invalid source address \"%s\".", local_address);
        return SR_ERR_INVAL_ARG;
    }

    return SR_ERR_OK;
}

/**
 * @brief Try to create and connect one UDP socket for a resolved destination.
 *
 * @param[in] rp Resolved destination address candidate.
 * @param[in] local_address Local source address string, if configured.
 * @param[in] local_addr Parsed local source address, if configured.
 * @param[in] local_addr_len Parsed local source address length.
 * @return Connected socket fd on success, -1 on failure.
 */
static int
udp_notif_connect_try_one(const struct addrinfo *rp, const char *local_address,
        const struct sockaddr_storage *local_addr, socklen_t local_addr_len)
{
    int sockfd;

    if (!rp) {
        return -1;
    }

    sockfd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    if (sockfd < 0) {
        return -1;
    }

    /* bind to local address */
    if (local_address) {
        if (bind(sockfd, (const struct sockaddr *)local_addr, local_addr_len) < 0) {
            SRNTF_LOG_ERR("Failed to bind UDP socket to local address \"%s\": %s.",
                    local_address, strerror(errno));
            close(sockfd);
            return -1;
        }
    }

    /* connect() on a UDP socket allows using send() instead of sendto() (simplicity),
     * enables receiving ICMP errors (error-handling) and is faster (route caching) */
    if (connect(sockfd, rp->ai_addr, rp->ai_addrlen) < 0) {
        close(sockfd);
        return -1;
    }

    return sockfd;
}

/*
 * ---------------------------------------------------------------------------
 * Transport ops callbacks
 * ---------------------------------------------------------------------------
 */

static int
udp_transport_connect_cb(notif_receiver_t *recv, void *cfg)
{
    int rc = SR_ERR_OK, sockfd = -1, r;
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;
    udp_conn_ctx_t *conn;
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[6];
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = 0;

    if (!udp_recv || !udp_recv->remote_address) {
        return SR_ERR_INVAL_ARG;
    }

    assert(!recv->ops || ((recv->ops->type == NOTIF_TRANSPORT_TYPE_UDP) && !recv->conn_ctx));

    if (recv->sub && recv->sub->local_address) {
        rc = udp_notif_local_addr_prepare(recv->sub->local_address, &local_addr, &local_addr_len);
        if (rc != SR_ERR_OK) {
            return rc;
        }
    }

    snprintf(port_str, sizeof(port_str), "%" PRIu16, udp_recv->remote_port);

    /* resolve destination address */
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;
    hints.ai_flags = 0;
    hints.ai_protocol = IPPROTO_UDP;

    r = getaddrinfo(udp_recv->remote_address, port_str, &hints, &res);
    if (r) {
        SRNTF_LOG_ERR("Failed to resolve address \"%s\": %s.", udp_recv->remote_address, gai_strerror(r));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    /* try each resolved address until one succeeds */
    for (rp = res; rp; rp = rp->ai_next) {
        if (recv->sub && recv->sub->local_address && (rp->ai_family != local_addr.ss_family)) {
            continue;
        }

        sockfd = udp_notif_connect_try_one(rp, recv->sub ? recv->sub->local_address : NULL,
                &local_addr, local_addr_len);
        if (sockfd >= 0) {
            break;
        }
    }

    if (sockfd < 0) {
        SRNTF_LOG_ERR("Failed to connect to \"%s:%s\": %s.", udp_recv->remote_address, port_str, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    conn = calloc(1, sizeof *conn);
    if (!conn) {
        ERRMEM;
        close(sockfd);
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }
    conn->sockfd = sockfd;
    recv->conn_ctx = conn;

    SRNTF_LOG_INF("Connected UDP-Notif receiver to %s:%s on socket %d.", udp_recv->remote_address, port_str, sockfd);

    /* initialize message ID to 1 as per spec (starts at 1 with first message) */
    if (udp_recv->message_id == 0) {
        ATOMIC_STORE_RELAXED(udp_recv->message_id, 1);
    }

    /* TODO: publisher_id should be configured or generated uniquely per publisher instance */
    if (udp_recv->publisher_id == 0) {
        udp_recv->publisher_id = (uint32_t)getpid();
    }

cleanup:
    freeaddrinfo(res);
    return rc;
}

static void
udp_transport_disconnect_cb(notif_receiver_t *recv)
{
    udp_conn_ctx_t *conn;

    if (!recv || !recv->conn_ctx) {
        return;
    }

    conn = (udp_conn_ctx_t *)recv->conn_ctx;
    assert(conn->sockfd >= 0);
    close(conn->sockfd);
    free(conn);
    recv->conn_ctx = NULL;
}

static int
udp_transport_is_connected_cb(const notif_receiver_t *recv)
{
    udp_conn_ctx_t *conn;

    if (!recv || !recv->conn_ctx) {
        return 0;
    }

    conn = (udp_conn_ctx_t *)recv->conn_ctx;
    return conn->sockfd >= 0 ? 1 : 0;
}

static int
udp_transport_send_cb(notif_receiver_t *recv, void *cfg,
        const struct lyd_node *notif, const struct timespec *timestamp, notif_encoding_t encoding)
{
    int rc;
    char *payload = NULL;
    size_t payload_len;
    udp_notif_media_type_t media_type;
    uint32_t message_id;
    uint16_t max_segment_size;
    size_t total_msg_len;
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;
    udp_conn_ctx_t *conn;

    (void)timestamp;

    if (!recv || !udp_recv || !notif) {
        return SR_ERR_INVAL_ARG;
    }

    if (!recv->conn_ctx) {
        SRNTF_LOG_ERR("UDP-Notif receiver is not connected.");
        return SR_ERR_OPERATION_FAILED;
    }

    conn = (udp_conn_ctx_t *)recv->conn_ctx;
    if (conn->sockfd < 0) {
        SRNTF_LOG_ERR("UDP-Notif receiver is not connected.");
        return SR_ERR_OPERATION_FAILED;
    }

    /* encode the notification */
    rc = notif_encode(notif, encoding, &payload, &payload_len);
    if (rc != SR_ERR_OK) {
        goto cleanup;
    }

    /* get media type */
    media_type = encoding_to_media_type(encoding);

    /* get current message ID and increment for next message atomically */
    message_id = ATOMIC_ADD_RELAXED(udp_recv->message_id, 1);

    /* determine max segment size */
    max_segment_size = udp_recv->max_segment_size;
    if (max_segment_size == 0) {
        max_segment_size = UDP_NOTIF_DEFAULT_MAX_SEGMENT_SIZE;
    }

    /* calculate total message length (header + payload) */
    total_msg_len = UDP_NOTIF_HDR_SIZE + payload_len;

    /* check if segmentation is needed */
    if (total_msg_len <= max_segment_size) {
        /* message fits in one segment, no segmentation needed */
        rc = udp_notif_send_unsegmented(recv, udp_recv, media_type, payload, payload_len, message_id);
    } else if (udp_recv->enable_segmentation) {
        /* message too large, use segmentation */
        rc = udp_notif_send_segmented(recv, udp_recv, media_type, payload, payload_len, message_id, max_segment_size);
    } else {
        /* message too large but segmentation disabled */
        SRNTF_LOG_ERR("Notification message too large (%zu bytes) and segmentation is disabled.",
                payload_len);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

cleanup:
    free(payload);
    return rc;
}

/*
 * ---------------------------------------------------------------------------
 * Config parse / change / destroy / validate callbacks
 * ---------------------------------------------------------------------------
 */

static int
udp_notif_receiver_from_node(const struct lyd_node *node, udp_notif_receiver_t *udp_recv)
{
    int rc = SR_ERR_OK;
    struct lyd_node *n;

    memset(udp_recv, 0, sizeof *udp_recv);

    if ((rc = get_descendant_mandatory(node, "remote-address", &n))) {
        goto cleanup;
    }
    udp_recv->remote_address = strdup(lyd_get_value(n));
    CHECK_ERRMEM_GOTO(udp_recv->remote_address, rc, cleanup);

    if ((rc = get_descendant_mandatory(node, "remote-port", &n))) {
        goto cleanup;
    }
    udp_recv->remote_port = (uint16_t)strtoul(lyd_get_value(n), NULL, 10);

    get_descendant_optional(node, "enable-segmentation", &n);
    if (n) {
        udp_recv->enable_segmentation = ((struct lyd_node_term *)n)->value.boolean;
    }

    get_descendant_optional(node, "max-segment-size", &n);
    if (n) {
        udp_recv->max_segment_size = (uint16_t)strtoul(lyd_get_value(n), NULL, 10);
    }

    ATOMIC_STORE_RELAXED(udp_recv->message_id, 1);

cleanup:
    return rc;
}

static int
udp_transport_config_parse_cb(const struct lyd_node *node, void **cfg)
{
    int rc = SR_ERR_OK;
    udp_notif_receiver_t *udp_recv;

    udp_recv = calloc(1, sizeof *udp_recv);
    CHECK_ERRMEM_RET(udp_recv);

    if ((rc = udp_notif_receiver_from_node(node, udp_recv))) {
        free(udp_recv);
        return rc;
    }

    *cfg = udp_recv;
    return SR_ERR_OK;
}

static void
udp_notif_receiver_destroy(udp_notif_receiver_t *udp_recv)
{
    if (!udp_recv) {
        return;
    }

    free(udp_recv->remote_address);
}

static void
udp_transport_config_destroy_cb(void *cfg)
{
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;

    udp_notif_receiver_destroy(udp_recv);
    free(udp_recv);
}

static int
udp_transport_config_change_cb(notif_receiver_inst_t *inst, const struct lyd_node *node, sr_change_oper_t op)
{
    int rc = SR_ERR_OK;
    const char *node_name;
    udp_notif_receiver_t *udp_recv = NULL;

    node_name = LYD_NAME(node);

    if (!strcmp(node_name, "udp-notif-receiver")) {
        if (op == SR_OP_CREATED) {
            inst->type = NOTIF_TRANSPORT_TYPE_UDP;
            inst->modified = 1;
            if (!inst->transport_config) {
                udp_recv = calloc(1, sizeof *udp_recv);
                CHECK_ERRMEM_GOTO(udp_recv, rc, cleanup);
                ATOMIC_STORE_RELAXED(udp_recv->message_id, 1);
                inst->transport_config = udp_recv;
            }
        } else if (op == SR_OP_DELETED) {
            inst->type = NOTIF_TRANSPORT_TYPE_NONE;
            inst->modified = 1;
            if (inst->transport_config) {
                udp_transport_config_destroy_cb(inst->transport_config);
                inst->transport_config = NULL;
            }
        }
    } else if (!strcmp(node_name, "remote-address")) {
        if (op == SR_OP_MODIFIED) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            free(udp_recv->remote_address);
            udp_recv->remote_address = strdup(lyd_get_value(node));
            CHECK_ERRMEM_GOTO(udp_recv->remote_address, rc, cleanup);
            inst->modified = 1;
        }
    } else if (!strcmp(node_name, "remote-port")) {
        if (op == SR_OP_MODIFIED) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            udp_recv->remote_port = (uint16_t)strtoul(lyd_get_value(node), NULL, 10);
            inst->modified = 1;
        }
    } else if (!strcmp(node_name, "enable-segmentation")) {
        if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            udp_recv->enable_segmentation = ((struct lyd_node_term *)node)->value.boolean;
        } else if (op == SR_OP_DELETED) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            udp_recv->enable_segmentation = 0;
        }
    } else if (!strcmp(node_name, "max-segment-size")) {
        if ((op == SR_OP_CREATED) || (op == SR_OP_MODIFIED)) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            udp_recv->max_segment_size = (uint16_t)strtoul(lyd_get_value(node), NULL, 10);
        } else if (op == SR_OP_DELETED) {
            udp_recv = (udp_notif_receiver_t *)inst->transport_config;
            udp_recv->max_segment_size = 0;
        }
    }

cleanup:
    return rc;
}

static int
udp_transport_config_validate_cb(const struct lyd_node *UNUSED(node))
{
    return SR_ERR_OK;
}

/*
 * ---------------------------------------------------------------------------
 * UDP transport ops vtable definition
 * ---------------------------------------------------------------------------
 */

const notif_transport_ops_t udp_transport_ops = {
    .name = "UDP",
    .transport_identity = "ietf-udp-notif-transport:udp-notif",
    .config_container_name = "udp-notif-receiver",
    .type = NOTIF_TRANSPORT_TYPE_UDP,
    .connect = udp_transport_connect_cb,
    .disconnect = udp_transport_disconnect_cb,
    .is_connected = udp_transport_is_connected_cb,
    .send = udp_transport_send_cb,
    .config_parse = udp_transport_config_parse_cb,
    .config_change = udp_transport_config_change_cb,
    .config_destroy = udp_transport_config_destroy_cb,
    .config_validate = udp_transport_config_validate_cb,
};
