/**
 * @file udp_notif_common.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief UDP-Notif collector internal types header
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

#ifndef _UDP_NOTIF_COMMON_H
#define _UDP_NOTIF_COMMON_H

#include <stdint.h>
#include <sys/socket.h>
#include <time.h>

#include "udp_notif.h"

/** Maximum UDP-Notif datagram size, limited by the 16-bit Message Length */
#define SRUDPN_MAX_DGRAM_SIZE 65535

/** Maximum number of segments of a message, limited by the 15-bit Segment Number */
#define SRUDPN_MAX_SEGMENTS 32768

/** Time after which an incomplete message is dropped, draft-ietf-netconf-udp-notif allows at most 20 s */
#define SRUDPN_REASM_TIMEOUT_MS 10000

/** Maximum number of messages being reassembled at once */
#define SRUDPN_MAX_PENDING 16

/** Maximum memory buffered by all the messages being reassembled, their segments and segment arrays */
#define SRUDPN_REASM_MAX_BYTES (64 * 1024 * 1024)

/** Requested size of the collector socket receive buffer */
#define SRUDPN_RCVBUF_SIZE (4 * 1024 * 1024)

/** RFC 5277 notification envelope XML namespace */
#define SRUDPN_RFC5277_XML_NS "urn:ietf:params:xml:ns:netconf:notification:1.0"

/** RFC 8040 notification envelope JSON module */
#define SRUDPN_RFC5277_JSON_MODULE "ietf-restconf"

/**
 * @brief Received segment of a message being reassembled.
 */
struct srudpn_seg {
    uint8_t *data;                  /**< segment data, NULL if not received yet */
    uint16_t len;                   /**< length of the segment data */
};

/**
 * @brief Message being reassembled.
 */
struct srudpn_reasm {
    uint32_t publisher_id;          /**< message publisher ID */
    uint32_t message_id;            /**< message ID */
    struct timespec first_ts;       /**< monotonic time the first segment was received */
    struct timespec last_ts;        /**< monotonic time the last segment was received */
    struct srudpn_seg *segs;        /**< sized array of segments indexed by their number */
    uint16_t received;              /**< number of received segments */
    uint32_t size;                  /**< memory buffered by the segments and the segment array */
    int32_t last;                   /**< number of the last segment, -1 if not received yet */
    srudpn_hdr_t hdr;               /**< header of segment 0, valid once it is received */
    struct sockaddr_storage src;    /**< source address and port of the segments */
};

/**
 * @brief Complete (reassembled) UDP-Notif message.
 */
struct srudpn_msg_s {
    srudpn_hdr_t hdr;               /**< header of segment 0, the one carrying all the options */
    uint8_t *payload;               /**< reassembled payload */
    uint32_t payload_len;           /**< length of the payload */
    struct sockaddr_storage src;    /**< source address and port, IPv4 for an IPv4-mapped IPv6 address */
};

/**
 * @brief Parsed notification of a UDP-Notif message.
 */
struct srudpn_notif_s {
    struct lyd_node *env;           /**< envelope tree */
    struct lyd_node *tree;          /**< notification data tree, separate from the envelope */
    struct timespec event_time;     /**< event time from the envelope */
};

/**
 * @brief UDP-Notif collector.
 */
struct srudpn_s {
    int fd;                         /**< bound UDP socket */
    uint16_t port;                  /**< bound port */
    srudpn_stats_t stats;           /**< diagnostic counters */
    struct srudpn_reasm *reasms;    /**< sized array of messages being reassembled */
};

#endif /* _UDP_NOTIF_COMMON_H */
