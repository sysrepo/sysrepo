/**
 * @file udp_notif.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief UDP-Notif (draft-ietf-netconf-udp-notif) collector and encoder functions header
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

#ifndef SYSREPO_UDP_NOTIF_H_
#define SYSREPO_UDP_NOTIF_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <net/if.h>
#include <netinet/in.h>
#include <stdint.h>
#include <time.h>

#include "sysrepo.h"

/**
 * @defgroup udp_notif_api UDP-Notif API
 *
 * @brief Collector and publisher of draft-ietf-netconf-udp-notif notifications.
 */

/**
 * @defgroup udp_notif_common Common
 * @ingroup udp_notif_api
 * @{
 *
 * @brief Constants and types shared by the collector and the publisher.
 */

/** UDP-Notif header version (draft-ietf-netconf-udp-notif-26) */
#define SRUDPN_VERSION 1

/** UDP-Notif fixed header size in octets */
#define SRUDPN_HDR_SIZE 12

/** UDP-Notif segmentation option type */
#define SRUDPN_OPT_SEGMENTATION 1

/** UDP-Notif segmentation option size in octets */
#define SRUDPN_OPT_SEGMENTATION_SIZE 4

/** Size of a buffer for a numeric source address, including the scope of an IPv6 one */
#define SRUDPN_ADDR_STRLEN (INET6_ADDRSTRLEN + IF_NAMESIZE)

/**
 * @brief UDP-Notif media types (MT values with the S-flag unset).
 */
typedef enum {
    SRUDPN_MT_JSON = 1,             /**< application/yang-data+json */
    SRUDPN_MT_XML = 2,              /**< application/yang-data+xml */
    SRUDPN_MT_CBOR = 3,             /**< application/yang-data+cbor, encoded and parsed only if libyang was built
                                         with CBOR support (LY_HAVE_CBOR) */
    SRUDPN_MT_PRIVATE = 16          /**< any media type of the private space (S-flag set), outside the 4-bit MT range */
} srudpn_media_type_t;

/**
 * @brief Parsed header of one UDP-Notif datagram.
 *
 * The header format is defined by https://datatracker.ietf.org/doc/draft-ietf-netconf-udp-notif/.
 */
typedef struct {
    uint8_t version;                /**< header version */
    uint8_t s_flag;                 /**< media type space, 1 for a private one */
    uint8_t media_type;             /**< media type, ::srudpn_media_type_t with S-flag unset */
    uint8_t header_len;             /**< header length in octets, including options */
    uint16_t message_len;           /**< datagram length in octets, including the header */
    uint32_t publisher_id;          /**< message publisher ID */
    uint32_t message_id;            /**< message ID */
    int segmented;                  /**< whether the segmentation option is present */
    uint16_t segment_num;           /**< segment number, only if segmented */
    int last_segment;               /**< whether this is the last segment, only if segmented */
} srudpn_hdr_t;

/** @} udp_notif_common */

/**
 * @defgroup udp_notif_collector Collector
 * @ingroup udp_notif_api
 * @{
 *
 * @brief Receiving, reassembling and parsing UDP-Notif messages.
 */

/**
 * @brief UDP-Notif collector diagnostic counters.
 */
typedef struct {
    uint32_t datagrams;             /**< all received datagrams */
    uint32_t messages;              /**< complete messages returned */
    uint32_t dup_segments;          /**< duplicate segments dropped */
    uint32_t malformed;             /**< datagrams discarded for an invalid header or length */
    uint32_t unsupported;           /**< datagrams discarded for a version, option or media type */
    uint32_t reasm_discarded;       /**< incomplete messages dropped on a timeout or eviction */
} srudpn_stats_t;

/**
 * @brief Complete (reassembled) UDP-Notif message.
 */
typedef struct srudpn_msg_s srudpn_msg_t;

/**
 * @brief Parsed notification of a UDP-Notif message.
 *
 * The notification is sent in the RFC 5277 envelope (RFC 8040 for JSON), the getters return these parts of it:
 * @code{.xml}
 * <notification xmlns="urn:ietf:params:xml:ns:netconf:notification:1.0">    <- srudpn_notif_get_envelope()
 *   <eventTime>2026-10-23T10:00:00Z</eventTime>                             <- srudpn_notif_get_event_time()
 *   <link-down xmlns="urn:example:interfaces">                              <- srudpn_notif_get_tree()
 *     <if-name>eth0</if-name>
 *   </link-down>
 * </notification>
 * @endcode
 */
typedef struct srudpn_notif_s srudpn_notif_t;

/**
 * @brief UDP-Notif collector receiving and reassembling notifications over UDP.
 */
typedef struct srudpn_s srudpn_t;

/**
 * @brief Open a UDP-Notif collector bound to a local address.
 *
 * @param[in] address Numeric IPv4 or IPv6 address to bind to, NULL for all local addresses.
 * @param[in] port Port to bind to, 0 for any free port.
 * @param[out] udp Created collector.
 * @return Error code (::SR_ERR_OK on success).
 */
int srudpn_open(const char *address, uint16_t port, srudpn_t **udp);

/**
 * @brief Get the socket of a collector for polling.
 *
 * The socket must not be closed or read from.
 *
 * @param[in] udp Collector to use.
 * @return Socket file descriptor.
 */
int srudpn_get_fd(const srudpn_t *udp);

/**
 * @brief Get the port a collector is bound to.
 *
 * @param[in] udp Collector to use.
 * @return Bound port.
 */
uint16_t srudpn_get_port(const srudpn_t *udp);

/**
 * @brief Get the diagnostic counters of a collector.
 *
 * @param[in] udp Collector to use.
 * @return Current counters.
 */
srudpn_stats_t srudpn_get_stats(const srudpn_t *udp);

/**
 * @brief Close a collector, any incomplete messages are dropped.
 *
 * @param[in] udp Collector to close.
 */
void srudpn_close(srudpn_t *udp);

/**
 * @brief Read one complete UDP-Notif message.
 *
 * @param[in] udp Collector to read from.
 * @param[in] timeout_ms Timeout of the whole call, -1 for infinite, 0 to only process the already queued datagrams
 * without waiting.
 * @param[out] msg Read message, free with ::srudpn_msg_free().
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_TIME_OUT if no message was completed in time or a signal interrupted the wait,
 * @return another error code on failure.
 */
int srudpn_read_msg(srudpn_t *udp, int32_t timeout_ms, srudpn_msg_t **msg);

/**
 * @brief Get the header of a message.
 *
 * @param[in] msg Message to use.
 * @return Header of the message.
 */
const srudpn_hdr_t *srudpn_msg_get_hdr(const srudpn_msg_t *msg);

/**
 * @brief Get the media type of a message.
 *
 * Only ::SRUDPN_MT_JSON, ::SRUDPN_MT_XML and ::SRUDPN_MT_CBOR can be parsed by ::srudpn_msg_parse(), any other
 * media type has to be decoded from ::srudpn_msg_get_payload() by the caller.
 *
 * @param[in] msg Message to use.
 * @return Media type, ::SRUDPN_MT_PRIVATE for any private one, an unknown standard one as its MT value.
 */
srudpn_media_type_t srudpn_msg_get_media_type(const srudpn_msg_t *msg);

/**
 * @brief Get the payload of a message.
 *
 * Meant for the media types ::srudpn_msg_parse() cannot parse, see ::srudpn_msg_get_media_type().
 *
 * @param[in] msg Message to use.
 * @param[out] payload Reassembled payload.
 * @param[out] payload_len Length of @p payload.
 */
void srudpn_msg_get_payload(const srudpn_msg_t *msg, const uint8_t **payload, uint32_t *payload_len);

/**
 * @brief Get the source address and port of a message.
 *
 * @param[in] msg Message to use.
 * @param[out] addr Buffer of ::SRUDPN_ADDR_STRLEN for the numeric IPv4 or IPv6 source address.
 * @param[out] port Source port.
 */
void srudpn_msg_get_source(const srudpn_msg_t *msg, char *addr, uint16_t *port);

/**
 * @brief Parse the notification of a message.
 *
 * @param[in] msg Message to parse.
 * @param[in] ly_ctx Libyang context to use for parsing.
 * @param[out] notif Parsed notification, free with ::srudpn_notif_free().
 * @return Error code (::SR_ERR_OK on success).
 */
int srudpn_msg_parse(const srudpn_msg_t *msg, const struct ly_ctx *ly_ctx, srudpn_notif_t **notif);

/**
 * @brief Free a message.
 *
 * @param[in] msg Message to free.
 */
void srudpn_msg_free(srudpn_msg_t *msg);

/**
 * @brief Get the notification data tree of a parsed notification.
 *
 * @param[in] notif Parsed notification to use.
 * @return Notification data tree.
 */
const struct lyd_node *srudpn_notif_get_tree(const srudpn_notif_t *notif);

/**
 * @brief Get the envelope of a parsed notification.
 *
 * The envelope is the outer notification element of RFC 5277 (RFC 8040 for JSON) with the eventTime, without the
 * notification data itself, see ::srudpn_notif_t.
 *
 * @note The envelope nodes are opaque (no schema), read them with LYD_NAME() and lyd_get_value().
 *
 * @param[in] notif Parsed notification to use.
 * @return Envelope data tree.
 */
const struct lyd_node *srudpn_notif_get_envelope(const srudpn_notif_t *notif);

/**
 * @brief Get the event time of a parsed notification.
 *
 * @param[in] notif Parsed notification to use.
 * @return Event time from the notification envelope.
 */
const struct timespec *srudpn_notif_get_event_time(const srudpn_notif_t *notif);

/**
 * @brief Free a parsed notification.
 *
 * @param[in] notif Parsed notification to free.
 */
void srudpn_notif_free(srudpn_notif_t *notif);

/** @} udp_notif_collector */

/**
 * @defgroup udp_notif_publisher Publisher
 * @ingroup udp_notif_api
 * @{
 *
 * @brief Encoding notifications into UDP-Notif datagrams.
 */

/**
 * @brief One encoded UDP-Notif datagram, header and data to be sent together.
 */
typedef struct {
    uint8_t hdr[SRUDPN_HDR_SIZE + SRUDPN_OPT_SEGMENTATION_SIZE]; /**< header including options */
    uint8_t hdr_len;                /**< used length of the header */
    const uint8_t *data;            /**< datagram data, points into the encoded payload */
    uint16_t data_len;              /**< length of the datagram data */
} srudpn_dgram_t;

/**
 * @brief Encode a notification in the RFC 5277 envelope.
 *
 * @param[in] notif Notification to encode.
 * @param[in] event_time Event time of the notification.
 * @param[in] media_type Media type to encode in.
 * @param[out] payload Encoded payload.
 * @param[out] payload_len Length of @p payload.
 * @return Error code (::SR_ERR_OK on success).
 */
int srudpn_encode_notification(const struct lyd_node *notif, const struct timespec *event_time,
        srudpn_media_type_t media_type, uint8_t **payload, uint32_t *payload_len);

/**
 * @brief Encode a payload into UDP-Notif datagrams.
 *
 * @param[in] media_type Media type of the payload, not ::SRUDPN_MT_PRIVATE.
 * @param[in] publisher_id Message publisher ID.
 * @param[in] message_id Message ID.
 * @param[in] payload Payload to send, @p dgrams point into it so it must not be freed before them.
 * @param[in] payload_len Length of @p payload.
 * @param[in] max_segment_size Maximum datagram size, segmenting the message if it does not fit, 0 to never segment.
 * @param[out] dgrams Address of a ::srudpn_dgram_t pointer set to the encoded datagrams as a libyang sized array,
 * iterate with LYA_FOR() and free with LYA_FREE().
 * @return ::SR_ERR_OK on success,
 * @return ::SR_ERR_INVAL_ARG if the payload is empty or does not fit into a datagram or the segments,
 * @return another error code on failure.
 */
int srudpn_build_dgrams(srudpn_media_type_t media_type, uint32_t publisher_id, uint32_t message_id,
        const uint8_t *payload, uint32_t payload_len, uint16_t max_segment_size, srudpn_dgram_t **dgrams);

/** @} udp_notif_publisher */

#ifdef __cplusplus
}
#endif

#endif /* SYSREPO_UDP_NOTIF_H_ */
