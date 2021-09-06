/**
 * @file shm_types.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM types
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SHM_TYPES_H
#define _SHM_TYPES_H

#include <sys/types.h>
#include <time.h>

#include "common_types.h"
#include "sysrepo_types.h"

/**
 * @brief Main SHM dependency type.
 */
typedef enum {
    SR_DEP_REF,         /**< Module reference (leafref, when, must). */
    SR_DEP_INSTID       /**< Instance-identifier. */
} sr_dep_type_t;

/**
 * @brief Main SHM module dependency.
 */
typedef struct {
    sr_dep_type_t type; /**< Dependency type. */
    off_t module;       /**< Dependant module name (offset in main SHM). */
    off_t path;         /**< Path of the node with the dependency (offset in main SHM). */
} sr_dep_t;

/**
 * @brief Main SHM RPC/action.
 */
typedef struct {
    off_t path;                 /**< Path of the RPC/action (offset in main SHM). */

    off_t in_deps;              /**< Input operation dependencies (offset in main SHM). */
    uint16_t in_dep_count;      /**< Input dependency count. */
    off_t out_deps;             /**< Output operation dependencies (offset in main SHM). */
    uint16_t out_dep_count;     /**< Output dependency count. */

    sr_rwlock_t lock;           /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     RPC/action subscriptions. */
    off_t subs;                 /**< Array of RPC/action subscriptions (offset in ext SHM). */
    uint32_t sub_count;         /**< Number of RPC/action subscriptions. */
} sr_rpc_t;

/**
 * @brief Main SHM notification.
 */
typedef struct {
    off_t path;                 /**< Path of the notification (offset in main SHM). */

    off_t deps;                 /**< Array of dependencies of the notification (offset in main SHM). */
    uint16_t dep_count;         /**< Number of dependencies. */
} sr_notif_t;

/**
 * @brief Main SHM module.
 */
typedef struct {
    struct sr_mod_lock_s {
        sr_rwlock_t data_lock;  /**< Process-shared lock for accessing module instance data. */

        pthread_mutex_t ds_lock;    /**< Process-shared lock for accessing DS lock information. */
        uint32_t ds_lock_sid;   /**< SID of the module data datastore lock (NETCONF lock), the data can be modified only
                                     by this session. If 0, the DS lock is not held. */
        struct timespec ds_lock_ts; /**< Timestamp of the datastore lock. */
    } data_lock_info[SR_DS_COUNT];  /**< Module data lock information for each datastore. */
    sr_rwlock_t replay_lock;    /**< Process-shared lock for accessing stored notifications for replay. */
    uint32_t ver;               /**< Module data version (non-zero). */

    off_t name;                 /**< Module name (offset in main SHM). */
    char rev[11];               /**< Module revision. */
    ATOMIC_T replay_supp;       /**< Whether module supports replay. */
    off_t plugins[SR_MOD_DS_PLUGIN_COUNT];  /**< Module plugin names (offsets in main SHM). */

    off_t features;             /**< Array of enabled features (off_t *) (offset in main SHM). */
    uint16_t feat_count;        /**< Number of enabled features. */
    off_t rpcs;                 /**< Array of RPCs/actions of the module (offset in main SHM). */
    uint16_t rpc_count;         /**< Number of RPCs/actions. */
    off_t notifs;               /**< Array of notifications of the module (offset in main SHM). */
    uint16_t notif_count;       /**< Number of notifications. */

    off_t deps;                 /**< Array of module data dependencies (offset in main SHM). */
    uint16_t dep_count;         /**< Number of module data dependencies. */
    off_t inv_deps;             /**< Array of inverse module data dependencies (off_t *) (offset in main SHM). */
    uint16_t inv_dep_count;     /**< Number of inverse module data dependencies. */

    struct {
        sr_rwlock_t lock;       /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     change subscriptions. */
        off_t subs;             /**< Array of change subscriptions (offset in ext SHM). */
        uint32_t sub_count;     /**< Number of change subscriptions. */
    } change_sub[SR_DS_COUNT];  /**< Change subscriptions for each datastore. */

    sr_rwlock_t oper_lock;      /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     operational subscriptions. */
    off_t oper_subs;            /**< Array of operational subscriptions (offset in ext SHM). */
    uint32_t oper_sub_count;    /**< Number of operational subscriptions. */

    sr_rwlock_t notif_lock;     /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     notification subscriptions. */
    off_t notif_subs;           /**< Array of notification subscriptions (offset in ext SHM). */
    uint32_t notif_sub_count;   /**< Number of notification subscriptions. */
} sr_mod_t;

/**
 * @brief Main SHM.
 */
typedef struct {
    uint32_t shm_ver;           /**< Main and ext SHM version of all expected data stored in them. Is increased with
                                     every change of their structure content (ABI change). */
    pthread_mutex_t lydmods_lock; /**< Process-shared lock for accessing sysrepo module data. */
    pthread_mutex_t ext_lock;   /**< Process-shared lock for accessing holes and truncating ext SHM. */
    uint32_t mod_count;         /**< Number of installed modules stored after this structure. */

    ATOMIC_T new_sr_cid;        /**< Connection ID for a new connection. */
    ATOMIC_T new_sr_sid;        /**< SID for a new session. */
    ATOMIC_T new_sub_id;        /**< Subscription ID of a new subscription. */
    ATOMIC_T new_evpipe_num;    /**< Event pipe number for a new subscription. */
} sr_main_shm_t;

/**
 * @brief Ext SHM module change subscriptions.
 */
typedef struct {
    off_t xpath;                /**< XPath of the subscription. */
    uint32_t priority;          /**< Subscription priority. */
    int opts;                   /**< Subscription options. */
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /**< Event pipe number. */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_change_sub_t;

/**
 * @brief Ext SHM module operational subscription type.
 */
typedef enum {
    SR_OPER_SUB_NONE = 0,         /**< Invalid type. */
    SR_OPER_SUB_STATE,            /**< Providing state data. */
    SR_OPER_SUB_CONFIG,           /**< Providing configuration data. */
    SR_OPER_SUB_MIXED             /**< Providing both state and configuration data. */
} sr_mod_oper_sub_type_t;

/**
 * @brief Ext SHM module operational subscription.
 */
typedef struct {
    off_t xpath;                /**< XPath of the subscription (offset in ext SHM). */
    sr_mod_oper_sub_type_t sub_type;  /**< Type of the subscription. */
    int opts;                   /**< Subscription options. */
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /** Event pipe number. */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_oper_sub_t;

/**
 * @brief Ext SHM notification subscription.
 */
typedef struct {
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /**< Event pipe number. */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_notif_sub_t;

/**
 * @brief Ext SHM module RPC/action subscription.
 */
typedef struct {
    off_t xpath;                /**< Full XPath of the RPC/action subscription (offset in ext SHM). */
    uint32_t priority;          /**< Subscription priority. */
    int opts;                   /**< Subscription options. */
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /**< Event pipe number. */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_rpc_sub_t;

/**
 * @brief Ext SHM structure.
 */
typedef struct {
    uint32_t first_hole_off;    /**< Offset of the first memory hole, 0 if there is none. */
} sr_ext_shm_t;

/**
 * @brief Ext SHM memory hole.
 */
typedef struct {
    uint32_t size;
    uint32_t next_hole_off;
} sr_ext_hole_t;

/**
 * @brief Generic (single-subscriber) subscription SHM structure.
 */
typedef struct {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    sr_cid_t orig_cid;          /**< Event originator CID. */
    uint32_t request_id;        /**< Request ID. */
    sr_sub_event_t event;       /**< Event. */
} sr_sub_shm_t;

/**
 * @brief Multi-subscriber subscription SHM structure.
 */
typedef struct {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    sr_cid_t orig_cid;          /**< Event originator CID. */
    uint32_t request_id;        /**< Request ID. */
    sr_sub_event_t event;       /**< Event. */

    /* specific fields */
    uint32_t priority;          /**< Priority of the subscriber. */
    uint32_t subscriber_count;  /**< Number of subscribers to process this event. */
} sr_multi_sub_shm_t;

#endif /* _SHM_TYPES_H */
