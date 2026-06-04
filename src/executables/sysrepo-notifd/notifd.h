/**
 * @file notifd.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief header of common functions for sysrepo-notifd
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

#ifndef NOTIFD_H_
#define NOTIFD_H_

#include <pthread.h>
#include <stdint.h>
#include <time.h>

#include "compat.h"
#include "sysrepo.h"
#include "sysrepo_types.h"

/**
 * @brief Logging macros for sysrepo-notifd.
 */
#define SRNTF_LOG_INF(...) SRPLG_LOG_INF("sysrepo-notifd", __VA_ARGS__)
#define SRNTF_LOG_WRN(...) SRPLG_LOG_WRN("sysrepo-notifd", __VA_ARGS__)
#define SRNTF_LOG_ERR(...) SRPLG_LOG_ERR("sysrepo-notifd", __VA_ARGS__)
#define SRNTF_LOG_DBG(...) SRPLG_LOG_DBG("sysrepo-notifd", __VA_ARGS__)

/**
 * @brief Log a validation error and, if the event is ::SR_EV_CHANGE, also set it on the session for the client.
 *
 * Use in validation callbacks so that the daemon log (stderr/stdout) always receives
 * the error message, while the originating client only gets it for ::SR_EV_CHANGE
 * (not for ::SR_EV_ENABLED, there is no originating client to report back to).
 */
#define SRNTF_VALIDATE_ERR(sess, event, err_code, ...) \
    do { \
        SRNTF_LOG_ERR(__VA_ARGS__); \
        if ((event) == SR_EV_CHANGE) { \
            sr_session_set_error(sess, NULL, err_code, __VA_ARGS__); \
        } \
    } while (0)

#define ERRMEM SRNTF_LOG_ERR("Memory allocation failed (%s:%d).", __FILE__, __LINE__)

#define CHECK_ERRMEM_GOTO(_ptr, _ret, _label) \
    do { \
        if (!(_ptr)) { \
            _ret = SR_ERR_NO_MEMORY; \
            ERRMEM; \
            goto _label; \
        } \
    } while (0)

#define CHECK_ERRMEM_RET(_ptr) \
    do { \
        if (!(_ptr)) { \
            ERRMEM; \
            return SR_ERR_NO_MEMORY; \
        } \
    } while (0)

/**
 * @brief Timeout for acquiring the main context config rwlock, in milliseconds.
 *
 * The main context config lock is used to synchronize access to the entire configuration,
 * so it may be held for longer periods during e.g. connection creation.
 */
#define NOTIFD_CONTEXT_LOCK_TIMEOUT_MS 10000

/**
 * @brief Base delay in seconds for receiver reconnect exponential backoff.
 */
#define NOTIFD_RECV_RECONNECT_BASE_SEC 1

/**
 * @brief Maximum delay in seconds for receiver reconnect exponential backoff.
 */
#define NOTIFD_RECV_RECONNECT_MAX_SEC 60

/* forward declarations */
typedef struct notifd_ctx_s notifd_ctx_t;
typedef struct notif_sub_s notif_sub_t;
typedef struct notif_receiver_s notif_receiver_t;
typedef struct notif_receiver_inst_s notif_receiver_inst_t;

/**
 * @brief State of a configured subscription.
 */
typedef enum {
    NOTIF_SUB_STATE_INVALID = 0,    /**< subscription parameters are not supportable */
    NOTIF_SUB_STATE_VALID,          /**< subscription is supportable with current parameters */
    NOTIF_SUB_STATE_CONCLUDED       /**< subscription has hit stop time, no active/suspended receivers */
} notif_sub_state_t;

/**
 * @brief State of a notification receiver within a subscription.
 */
typedef enum {
    NOTIF_RECV_STATE_CONNECTING = 0,    /**< awaiting initial connection and subscription-started delivery */
    NOTIF_RECV_STATE_DISCONNECTED,      /**< connection attempt failed, not currently reconnecting */
    NOTIF_RECV_STATE_ACTIVE,            /**< receiver is connected and receiving notifications */
    NOTIF_RECV_STATE_SUSPENDED          /**< publisher unable to provide notifications (not yet implemented) */
} notif_recv_state_t;

/**
 * @brief Notification transport type.
 */
typedef enum {
    NOTIF_TRANSPORT_TYPE_NONE = 0,  /**< no transport configured */
    NOTIF_TRANSPORT_TYPE_UDP        /**< UDP transport */
} notif_transport_type_t;

/**
 * @brief Notification encoding type.
 */
typedef enum {
    NOTIF_ENCODING_UNSET = 0,   /**< not set, left to the underlying transport default */
    NOTIF_ENCODING_XML,         /**< XML encoding */
    NOTIF_ENCODING_JSON,        /**< JSON encoding */
    NOTIF_ENCODING_CBOR         /**< CBOR encoding */
} notif_encoding_t;

/**
 * @brief Establish a transport connection for a notification receiver.
 *
 * Called when a receiver needs to connect to its configured destination.
 * On success, must allocate and set @p recv->conn_ctx to a transport-specific
 * connection context. The caller ensures the receiver is not already connected.
 *
 * @param[in] recv Receiver to connect. @p recv->inst and @p recv->ops are set.
 * @param[in] cfg Transport-specific configuration (from @p recv->inst->transport_config).
 * @return SR_ERR_OK on success, error code on failure (receiver remains disconnected).
 */
typedef int (*notif_transport_connect_cb)(notif_receiver_t *recv, void *cfg);

/**
 * @brief Tear down a transport connection for a notification receiver.
 *
 * Called when a receiver must be disconnected. Must close any transport resources
 * (sockets, file descriptors, etc.), free @p recv->conn_ctx, and set it to NULL.
 * The caller ensures the receiver is currently connected.
 *
 * @param[in] recv Receiver to disconnect. @p recv->conn_ctx is non-NULL.
 */
typedef void (*notif_transport_disconnect_cb)(notif_receiver_t *recv);

/**
 * @brief Check whether a notification receiver is currently connected.
 *
 * @param[in] recv Receiver to check.
 * @return 1 if connected, 0 otherwise.
 */
typedef int (*notif_transport_is_connected_cb)(const notif_receiver_t *recv);

/**
 * @brief Send a notification over the transport to a receiver.
 *
 * Encodes and transmits a single notification using the given encoding.
 * The caller ensures the receiver is connected before calling.
 *
 * @param[in] recv Receiver to send to. @p recv->conn_ctx is non-NULL.
 * @param[in] cfg Transport-specific configuration (from @p recv->inst->transport_config).
 * @param[in] notif Notification data tree to send.
 * @param[in] ts Notification event timestamp.
 * @param[in] encoding Encoding format for the notification payload.
 * @return SR_ERR_OK on success, error code on failure.
 */
typedef int (*notif_transport_send_cb)(notif_receiver_t *recv, void *cfg, const struct lyd_node *notif,
        const struct timespec *ts, notif_encoding_t encoding);

/**
 * @brief Parse transport configuration from a YANG data node.
 *
 * Called when a receiver instance is created from the YANG datastore.
 * Must allocate and fill a transport-specific configuration structure
 * and return it via @p cfg. The returned pointer is owned by the caller
 * and will later be freed via ::notif_transport_config_destroy_cb.
 *
 * @param[in] node Root YANG node of the transport-specific config container
 *             (e.g. the "udp-notif-receiver" NP container).
 * @param[out] cfg Newly allocated transport-specific configuration.
 * @return SR_ERR_OK on success, error code on failure (*cfg is untouched).
 */
typedef int (*notif_transport_config_parse_cb)(const struct lyd_node *node, void **cfg);

/**
 * @brief Handle an incremental configuration change for a receiver instance.
 *
 * Called for each YANG node that was created, modified, or deleted within
 * a receiver instance. The implementation must update @p inst->transport_config
 * in place and set @p inst->modified if the change requires receivers to reconnect.
 *
 * For the transport NP container itself (e.g. "udp-notif-receiver"), SR_OP_CREATED
 * means the transport type is being set and the config should be initialized;
 * SR_OP_DELETED means the transport is being removed and the config should be freed.
 *
 * @param[in] inst Receiver instance being modified. @p inst->transport_config may be NULL
 *             if the transport container has not been created yet.
 * @param[in] node Changed YANG data node.
 * @param[in] op Sysrepo change operation (SR_OP_CREATED, SR_OP_MODIFIED, SR_OP_DELETED).
 * @return SR_ERR_OK on success, error code on failure.
 */
typedef int (*notif_transport_config_change_cb)(notif_receiver_inst_t *inst,
        const struct lyd_node *node, sr_change_oper_t op);

/**
 * @brief Free a transport-specific configuration structure.
 *
 * Called when a receiver instance is being destroyed or when the transport
 * container is deleted. Must release all memory held by @p cfg.
 *
 * @param[in] cfg Transport-specific configuration to free (may be NULL).
 */
typedef void (*notif_transport_config_destroy_cb)(void *cfg);

/**
 * @brief Validate transport configuration for a subscription.
 *
 * Called during subscription validation (SR_EV_CHANGE || SR_EV_ENABLED) to check that the transport-specific
 * configuration under the subscription's receiver instance is valid and
 * supportable. The @p node is the subscription YANG node (not the transport
 * config container), allowing cross-validation between subscription parameters
 * and transport capabilities.
 *
 * @param[in] node Subscription YANG data node containing the transport reference.
 * @return SR_ERR_OK if valid, error code otherwise.
 */
typedef int (*notif_transport_config_validate_cb)(const struct lyd_node *node);

/**
 * @brief Transport operations vtable.
 *
 * Each transport type implements this interface, enabling polymorphic
 * connect/disconnect/send/config operations without switch statements.
 */
typedef struct notif_transport_ops_s {
    const char *name;                                   /**< human-readable transport name (e.g. "UDP") */
    const char *transport_identity;                     /**< YANG identity value (e.g. "ietf-udp-notif-transport:udp-notif") */
    const char *config_container_name;                  /**< NP container name under receiver-instance (e.g. "udp-notif-receiver") */
    notif_transport_type_t type;                        /**< transport type enum value */

    notif_transport_connect_cb connect;                 /**< establish transport connection */
    notif_transport_disconnect_cb disconnect;           /**< tear down transport connection */
    notif_transport_is_connected_cb is_connected;       /**< check if transport is connected */
    notif_transport_send_cb send;                       /**< send a notification */

    notif_transport_config_parse_cb config_parse;       /**< parse config from YANG datastore */
    notif_transport_config_change_cb config_change;     /**< handle incremental config changes */
    notif_transport_config_destroy_cb config_destroy;   /**< free transport config */
    notif_transport_config_validate_cb config_validate; /**< validate transport config */
} notif_transport_ops_t;

/**
 * @brief Receiver instance shared by subscriptions.
 * Corresponds to /ietf-subscribed-notifications:receiver-instances/receiver-instance.
 *
 * Holds transport configuration and is referenced by subscription receivers.
 */
struct notif_receiver_inst_s {
    char *name;                             /**< receiver instance name */

    int modified;                           /**< whether the instance was modified and needs reconnect */

    notif_transport_type_t type;            /**< configured transport type */
    const notif_transport_ops_t *ops;       /**< transport operations vtable */
    void *transport_config;                 /**< transport-specific configuration (owned by the transport ops) */
};

/**
 * @brief Callback data passed to ::srsn_notif_cb().
 */
typedef struct notif_cb_data_s {
    notifd_ctx_t *ctx;          /**< main daemon context */
    notif_receiver_t *recv;     /**< receiver to send the notification to */
    notif_encoding_t encoding;  /**< notification encoding to use for sending */
} notif_cb_data_t;

/**
 * @brief Receiver within a subscription.
 * Corresponds to /ietf-subscribed-notifications:subscriptions/subscription/receivers/receiver
 *
 * References a receiver instance, which holds the actual transport configuration.
 */
struct notif_receiver_s {
    char *name;                                 /**< receiver name */

    notif_recv_state_t state;                   /**< current receiver state */
    notif_receiver_inst_t *inst;                /**< resolved reference to the receiver instance */

    const notif_transport_ops_t *ops;           /**< transport operations vtable (copied from inst) */
    void *conn_ctx;                             /**< transport-specific connection context (owned by the transport ops) */

    struct {
        sr_subscription_ctx_t *sr_subscr;       /**< sysrepo subscription context */
        uint32_t sub_id;                        /**< srsn subscription ID */
        int fd;                                 /**< notification pipe FD from srsn_subscribe */
    } srsn_data;                                /**< srsn subscription and dispatch data */
    notif_cb_data_t cb_data;                    /**< callback data for srsn dispatch */

    notif_sub_t *sub;                           /**< back-pointer to the parent subscription */
    struct timespec last_reconnect_attempt;     /**< time of the last reconnect attempt */
    uint32_t reconnect_attempts;                /**< number of consecutive failed reconnect attempts */

};

/**
 * @brief Configured subscription context.
 * Corresponds to /ietf-subscribed-notifications:subscriptions/subscription
 */
struct notif_sub_s {
    uint32_t id;                        /**< subscription ID */

    notif_sub_state_t state;            /**< subscription state */

    int resubscribe;                    /**< whether the subscription needs to be resubscribed to apply changes */
    int modified;                       /**< whether the subscription was modified */
    const char *modif_err_reason;       /**< YANG identity-ref reason the subscription is invalid, used in subscription-terminated */

    char *stream;                       /**< stream name */
    char *filter_ref;                   /**< optional stream filter name (e.g., XPath or subtree filter) */
    char *xpath_filter;                 /**< optional XPath filter */
    notif_encoding_t encoding;          /**< notification encoding */
    struct timespec stop_time;          /**< optional stop time */
    int replay;                         /**< whether to replay notifications */
    struct timespec start_time;         /**< requested replay start time for configured-replay */
    struct timespec replay_start_time;  /**< actual replay start time returned by srsn_subscribe */
    char *purpose;                      /**< purpose of the subscription */
    char *local_address;                /**< local address to send notifications from (NULL means OS default) */

    notif_receiver_t *receivers;        /**< receivers of this subscription (sized-array, see libyang docs) */
};

/**
 * @brief Main daemon context.
 */
struct notifd_ctx_s {
    sr_session_ctx_t *sr_sess;              /**< sysrepo session used by the daemon */
    pthread_rwlock_t state_rwlock;          /**< synchronize access to daemon shared state (subscriptions,
                                                 receiver instances, and related runtime fields) */
    pthread_mutex_t config_apply_mutex;     /**< serialize config-apply operations; keeps a single apply
                                                 transaction active so state_rwlock write-lock ownership
                                                 cannot be stolen across temporary unlock/relock windows */

    notif_sub_t **subs;                     /**< configured subscriptions (sized-array, see libyang docs) */
    notif_receiver_inst_t **recv_insts;     /**< configured receiver instances (sized-array, see libyang docs) */
};

#endif /* NOTIFD_H_ */
