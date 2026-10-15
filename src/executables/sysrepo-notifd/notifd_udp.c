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
#include <sys/random.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "compat.h"
#include "notifd.h"
#include "notifd_common.h"
#include "utils/udp_notif.h"

#include <libyang/libyang.h>

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

    ATOMIC_T message_id;        /**< monotonically increasing message ID, starts random */
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
 * @brief Convert notification encoding to UDP-Notif media type.
 *
 * @param[in] encoding Notification encoding, must be resolved (not ::NOTIF_ENCODING_UNSET).
 * @param[out] media_type Set to the UDP-Notif media type value.
 * @return SR_ERR_OK on success, error code on failure.
 */
static int
encoding_to_media_type(notif_encoding_t encoding, srudpn_media_type_t *media_type)
{
    int rc = SR_ERR_OK;

    switch (encoding) {
    case NOTIF_ENCODING_XML:
        *media_type = SRUDPN_MT_XML;
        break;
    case NOTIF_ENCODING_JSON:
        *media_type = SRUDPN_MT_JSON;
        break;
    case NOTIF_ENCODING_CBOR:
        *media_type = SRUDPN_MT_CBOR;
        break;
    case NOTIF_ENCODING_UNSET:
    default:
        SRNTF_LOG_ERR("Encoding must be resolved before notification serialization.");
        rc = SR_ERR_INVAL_ARG;
        break;
    }

    return rc;
}

/**
 * @brief Send a single UDP-Notif datagram.
 *
 * @param[in] recv Notification receiver.
 * @param[in] dgram Datagram to send.
 * @return SR_ERR_OK on success,
 * @return SR_ERR_TIME_OUT if the send buffer is full and the datagram was dropped,
 * @return another error code on failure.
 */
static int
udp_notif_dgram_send(notif_receiver_t *recv, const srudpn_dgram_t *dgram)
{
    udp_conn_ctx_t *conn;
    struct iovec iov[2];
    struct msghdr msg = {0};
    ssize_t sent;
    uint32_t len = dgram->hdr_len + dgram->data_len;

    assert(recv && recv->ops && (recv->ops->type == NOTIF_TRANSPORT_TYPE_UDP) && recv->conn_ctx);

    conn = (udp_conn_ctx_t *)recv->conn_ctx;
    assert(conn->sockfd >= 0);

    /* the header and the data sent as one datagram */
    iov[0].iov_base = (void *)dgram->hdr;
    iov[0].iov_len = dgram->hdr_len;
    iov[1].iov_base = (void *)dgram->data;
    iov[1].iov_len = dgram->data_len;
    msg.msg_iov = iov;
    msg.msg_iovlen = 2;

    sent = sendmsg(conn->sockfd, &msg, 0);
    if (sent < 0) {
        if ((errno == EAGAIN) || (errno == EWOULDBLOCK)) {
            /* the socket buffer is full, drop the datagram */
            return SR_ERR_TIME_OUT;
        }
        SRNTF_LOG_ERR("Failed to send UDP-Notif message to receiver \"%s\": %s.", recv->name, strerror(errno));
        return SR_ERR_SYS;
    }

    if ((uint32_t)sent != len) {
        SRNTF_LOG_ERR("Incomplete UDP-Notif send to receiver \"%s\": sent %zd of %" PRIu32 " bytes.", recv->name, sent, len);
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
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
 * @brief Create and connect one non-blocking UDP socket for a destination address.
 *
 * @param[in] addr Destination address.
 * @param[in] addr_len Length of @p addr.
 * @param[in] local_address Local source address string, if configured.
 * @param[in] local_addr Parsed local source address, if configured.
 * @param[in] local_addr_len Parsed local source address length.
 * @return Connected socket fd on success, -1 on failure.
 */
static int
udp_notif_socket_connect(const struct sockaddr *addr, socklen_t addr_len, const char *local_address,
        const struct sockaddr_storage *local_addr, socklen_t local_addr_len)
{
    int sockfd;

    /* non-blocking, sending must never block the dispatch loop */
    sockfd = socket(addr->sa_family, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_UDP);
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
    if (connect(sockfd, addr, addr_len) < 0) {
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
udp_transport_resolve_cb(notif_receiver_t *recv, void *cfg)
{
    int rc = SR_ERR_OK, r;
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;
    struct addrinfo hints, *res = NULL, *rp;
    char port_str[6];
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = 0;

    if (!udp_recv || !udp_recv->remote_address) {
        return SR_ERR_INVAL_ARG;
    }

    if (recv->sub && recv->sub->local_address) {
        /* only to learn the family the destination must match, the socket is created when connecting */
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
        SRNTF_LOG_ERR("Failed to resolve address \"%s\" of receiver \"%s\": %s.", udp_recv->remote_address,
                recv->name, gai_strerror(r));
        return SR_ERR_SYS;
    }

    /* remember the first resolved address of the family the source address dictates */
    for (rp = res; rp; rp = rp->ai_next) {
        if (recv->sub && recv->sub->local_address && (rp->ai_family != local_addr.ss_family)) {
            continue;
        }

        memcpy(&recv->addr, rp->ai_addr, rp->ai_addrlen);
        recv->addr_len = rp->ai_addrlen;
        break;
    }

    if (!rp) {
        SRNTF_LOG_ERR("No resolved address of \"%s:%s\" of receiver \"%s\" matches the family of the configured "
                "source address.", udp_recv->remote_address, port_str, recv->name);
        rc = SR_ERR_SYS;
    }

    freeaddrinfo(res);
    return rc;
}

static int
udp_transport_connect_cb(notif_receiver_t *recv, void *cfg)
{
    int rc = SR_ERR_OK, sockfd = -1;
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;
    udp_conn_ctx_t *conn;
    struct sockaddr_storage local_addr;
    socklen_t local_addr_len = 0;
    uint32_t message_id;

    if (!udp_recv || !udp_recv->remote_address) {
        return SR_ERR_INVAL_ARG;
    }

    assert((recv->ops->type == NOTIF_TRANSPORT_TYPE_UDP) && !recv->conn_ctx);

    if (!recv->addr_len) {
        /* the address is resolved only when the configuration is applied */
        SRNTF_LOG_ERR("Receiver \"%s\" has no resolved address, apply its configuration again or reset it.",
                recv->name);
        return SR_ERR_OPERATION_FAILED;
    }

    if (recv->sub && recv->sub->local_address) {
        rc = udp_notif_local_addr_prepare(recv->sub->local_address, &local_addr, &local_addr_len);
        if (rc != SR_ERR_OK) {
            return rc;
        }
    }

    /* the first message ID is random */
    if (!ATOMIC_LOAD_RELAXED(udp_recv->message_id)) {
        if (getrandom(&message_id, sizeof message_id, 0) != sizeof message_id) {
            SRNTF_LOG_ERR("Failed to generate the first UDP-Notif message ID: %s.", strerror(errno));
            return SR_ERR_SYS;
        }
        ATOMIC_STORE_RELAXED(udp_recv->message_id, message_id);
    }

    sockfd = udp_notif_socket_connect((const struct sockaddr *)&recv->addr, recv->addr_len,
            recv->sub ? recv->sub->local_address : NULL, &local_addr, local_addr_len);
    if (sockfd < 0) {
        SRNTF_LOG_ERR("Failed to connect to \"%s:%" PRIu16 "\": %s.", udp_recv->remote_address,
                udp_recv->remote_port, strerror(errno));
        return SR_ERR_SYS;
    }

    conn = calloc(1, sizeof *conn);
    if (!conn) {
        ERRMEM;
        close(sockfd);
        return SR_ERR_NO_MEMORY;
    }
    conn->sockfd = sockfd;
    recv->conn_ctx = conn;

    SRNTF_LOG_INF("Connected UDP-Notif receiver to %s:%" PRIu16 " on socket %d.", udp_recv->remote_address,
            udp_recv->remote_port, sockfd);

    /* TODO: publisher_id should be configured or generated uniquely per publisher instance */
    if (udp_recv->publisher_id == 0) {
        udp_recv->publisher_id = (uint32_t)getpid();
    }

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
    uint8_t *payload = NULL;
    uint32_t payload_len, message_id;
    LYA_COUNT_T i;
    srudpn_media_type_t media_type;
    srudpn_dgram_t *dgrams = NULL;
    uint16_t max_segment_size;
    udp_notif_receiver_t *udp_recv = (udp_notif_receiver_t *)cfg;
    udp_conn_ctx_t *conn;

    if (!recv || !udp_recv || !notif || !timestamp) {
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

    /* get media type */
    if ((rc = encoding_to_media_type(encoding, &media_type))) {
        goto cleanup;
    }

    /* encode the notification in the RFC 5277 <notification> envelope */
    if ((rc = srudpn_encode_notification(notif, timestamp, media_type, &payload, &payload_len))) {
        goto cleanup;
    }

    /* get current message ID and increment for next message atomically */
    message_id = ATOMIC_ADD_RELAXED(udp_recv->message_id, 1);

    /* determine max segment size */
    max_segment_size = udp_recv->max_segment_size;
    if (max_segment_size == 0) {
        max_segment_size = UDP_NOTIF_DEFAULT_MAX_SEGMENT_SIZE;
    }

    if (!udp_recv->enable_segmentation && (SRUDPN_HDR_SIZE + payload_len > max_segment_size)) {
        /* message too large but segmentation disabled */
        SRNTF_LOG_ERR("Notification message too large (%" PRIu32 " bytes) and segmentation is disabled.",
                payload_len);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }

    /* split the message into datagrams, segmented only if it does not fit into one */
    if ((rc = srudpn_build_dgrams(media_type, udp_recv->publisher_id, message_id, payload, payload_len,
            max_segment_size, &dgrams))) {
        goto cleanup;
    }

    LYA_FOR(dgrams, i) {
        if ((rc = udp_notif_dgram_send(recv, &dgrams[i]))) {
            /* abandon the remaining segments, the receiver discards a partial message */
            break;
        }
    }

cleanup:
    LYA_FREE(dgrams);
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

/**
 * @brief Get the default UDP-Notif encoding, the first implemented encoding whose YANG feature is enabled.
 *
 * @param[in] ly_ctx libyang context used for checking enabled features.
 * @return Default encoding or ::NOTIF_ENCODING_UNSET if none is usable.
 */
static notif_encoding_t
udp_transport_default_encoding_cb(const struct ly_ctx *ly_ctx)
{
    return notif_encoding_resolve_default(ly_ctx);
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
    .resolve = udp_transport_resolve_cb,
    .connect = udp_transport_connect_cb,
    .disconnect = udp_transport_disconnect_cb,
    .is_connected = udp_transport_is_connected_cb,
    .send = udp_transport_send_cb,
    .config_parse = udp_transport_config_parse_cb,
    .config_change = udp_transport_config_change_cb,
    .config_destroy = udp_transport_config_destroy_cb,
    .config_validate = udp_transport_config_validate_cb,
    .default_encoding = udp_transport_default_encoding_cb,
};
