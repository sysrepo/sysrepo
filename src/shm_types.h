/**
 * @file shm_types.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM types
 *
 * @copyright
 * Copyright (c) 2018 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2023 CESNET, z.s.p.o.
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

#include "compat.h"

#include "common_types.h"
#include "sysrepo_types.h"

#define SR_SHM_VER 16   /**< Main, mod, and ext SHM version of their expected content structures. */
#define SR_MAIN_SHM_LOCK "sr_main_lock"     /**< Main SHM file lock name. */

/**
 * Main SHM organization
 *
 * Except for main, mod, and ext SHM there are individual SHM segments for subscriptions and
 * running data files.
 */

/** Whether an event is one to be processed by the listeners (subscribers). */
#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_OPER) || (ev == SR_SUB_EV_RPC) \
        || (ev == SR_SUB_EV_NOTIF))

/** Whether an event is one to be processed by the originators. */
#define SR_IS_NOTIFY_EVENT(ev) ((ev == SR_SUB_EV_SUCCESS) || (ev == SR_SUB_EV_ERROR))

/**
 * @brief Mod SHM dependency type.
 */
typedef enum {
    SR_DEP_LREF,    /**< Leafref. */
    SR_DEP_INSTID,  /**< Instance-identifier. */
    SR_DEP_XPATH    /**< XPath (must or when). */
} sr_dep_type_t;

/**
 * @brief Mod SHM module dependency.
 */
typedef struct {
    sr_dep_type_t type;                 /**< Dependency type. */

    union {
        struct {
            off_t target_path;          /**< Leafref target (offset in mod SHM). */
            off_t target_module;        /**< Leafref target module name (offset in mod SHM). */
        } lref;                         /**< Leafref dependency. */
        struct {
            off_t source_path;          /**< Instance-identifier source path (offset in mod SHM). */
            off_t default_target_path;  /**< Instance-identifier default value, if any (offset in mod SHM). */
        } instid;                       /**< Instance-identifier dependency. */
        struct {
            off_t expr;                 /**< XPath expression (offset in mod SHM). */
            off_t target_modules;       /**< Dependant module names of XPath, if any (offset in mod SHM). */
            uint16_t target_mod_count;  /**< Dependant module name count. */
        } xpath;                        /**< XPath (must or when) dependency. */
    };
} sr_dep_t;

/**
 * @brief Mod SHM RPC/action.
 */
typedef struct {
    off_t path;                 /**< Path of the RPC/action (offset in mod SHM). */

    off_t in_deps;              /**< Input operation dependencies (offset in mod SHM). */
    uint16_t in_dep_count;      /**< Input dependency count. */
    off_t out_deps;             /**< Output operation dependencies (offset in mod SHM). */
    uint16_t out_dep_count;     /**< Output dependency count. */

    sr_rwlock_t lock;           /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     RPC/action subscriptions. */
    off_t subs;                 /**< Array of RPC/action subscriptions (offset in ext SHM). */
    uint32_t sub_count;         /**< Number of RPC/action subscriptions. */
} sr_rpc_t;

/**
 * @brief Mod SHM notification.
 */
typedef struct {
    off_t path;                 /**< Path of the notification (offset in mod SHM). */

    off_t deps;                 /**< Array of dependencies of the notification (offset in mod SHM). */
    uint16_t dep_count;         /**< Number of dependencies. */
} sr_notif_t;

/**
 * @brief Mod SHM module.
 */
typedef struct {
    struct sr_mod_lock_s {
        sr_rwlock_t data_lock;  /**< Process-shared lock for accessing module instance data. */

        pthread_mutex_t ds_lock;    /**< Process-shared lock for accessing DS lock information. */
        uint32_t ds_lock_sid;   /**< SID of the module data datastore lock (NETCONF lock), the data can be modified only
                                     by this session. If 0, the DS lock is not held. */
        struct timespec ds_lock_ts; /**< Timestamp of the datastore lock. */
        uint32_t prio;              /**< Module change priority synchronized with applying data changes. */
    } data_lock_info[SR_DS_COUNT];  /**< Module data lock information for each datastore. */
    sr_rwlock_t replay_lock;    /**< Process-shared lock for accessing stored notifications for replay. */

    off_t name;                 /**< Module name (offset in mod SHM). */
    char rev[11];               /**< Module revision. */
    int replay_supp;            /**< Whether module supports replay. */
    uint32_t run_cache_id;      /**< Running cached data ID. */
    off_t plugins[SR_MOD_DS_PLUGIN_COUNT];  /**< Module plugin names (offsets in mod SHM). */

    off_t features;             /**< Array of enabled features (off_t *) (offset in mod SHM). */
    uint16_t feat_count;        /**< Number of enabled features. */
    off_t rpcs;                 /**< Array of RPCs/actions of the module (offset in mod SHM). */
    uint16_t rpc_count;         /**< Number of RPCs/actions. */
    off_t notifs;               /**< Array of notifications of the module (offset in mod SHM). */
    uint16_t notif_count;       /**< Number of notifications. */

    off_t deps;                 /**< Array of module data dependencies (offset in mod SHM). */
    uint16_t dep_count;         /**< Number of module data dependencies. */
    off_t inv_deps;             /**< Array of inverse module data dependencies (off_t *) (offset in mod SHM). */
    uint16_t inv_dep_count;     /**< Number of inverse module data dependencies. */

    struct {
        sr_rwlock_t lock;       /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     change subscriptions. */
        off_t subs;             /**< Array of change subscriptions (offset in ext SHM). */
        uint32_t sub_count;     /**< Number of change subscriptions. */
    } change_sub[SR_DS_COUNT];  /**< Change subscriptions for each datastore. */

    sr_rwlock_t oper_get_lock;  /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     operational get subscriptions. */
    off_t oper_get_subs;        /**< Array of operational get subscriptions (offset in ext SHM). */
    uint32_t oper_get_sub_count; /**< Number of operational get subscriptions. */

    sr_rwlock_t oper_poll_lock; /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     operational poll subscriptions. */
    off_t oper_poll_subs;       /**< Array of operational poll subscriptions (offset in ext SHM). */
    uint32_t oper_poll_sub_count; /**< Number of operational poll subscriptions. */

    sr_rwlock_t notif_lock;     /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     notification subscriptions. */
    off_t notif_subs;           /**< Array of notification subscriptions (offset in ext SHM). */
    uint32_t notif_sub_count;   /**< Number of notification subscriptions. */

    sr_rwlock_t rpc_ext_lock;   /**< Process-shared lock for reading or preventing changes (READ) or modifying (WRITE)
                                     ext RPC subscriptions. */
    off_t rpc_ext_subs;         /**< Array of ext RPC subscriptions (offset in ext SHM). */
    uint32_t rpc_ext_sub_count; /**< Number of ext RPC subscriptions. */
} sr_mod_t;

/**
 * @brief Mod SHM structure
 */
typedef struct {
    uint32_t mod_count;         /**< Number of installed modules stored after this structure. */
} sr_mod_shm_t;

/**
 * @brief Main SHM structure.
 */
typedef struct {
    uint32_t shm_ver;           /**< Main and ext SHM version of all expected data stored in them. Is increased with
                                     every change of their structure content (ABI change). */
    pthread_mutex_t ext_lock;   /**< Process-shared lock for accessing holes and truncating ext SHM. */

    sr_rwlock_t context_lock;   /**< Process-shared lock for accessing connection LY context, lydmods data,
                                     and SHM mod modules. */
    pthread_mutex_t lydmods_lock;   /**< Process-shared lock for modifying SR internal module data. */
    uint32_t content_id;        /**< Context content ID of the latest context. */

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
 * @brief Ext SHM module operational get subscription type.
 */
typedef enum {
    SR_OPER_GET_SUB_NONE = 0,   /**< Invalid type. */
    SR_OPER_GET_SUB_STATE,      /**< Providing state data. */
    SR_OPER_GET_SUB_CONFIG,     /**< Providing configuration data. */
    SR_OPER_GET_SUB_MIXED       /**< Providing both state and configuration data. */
} sr_mod_oper_get_sub_type_t;

/**
 * @brief Ext SHM module operational XPath get subscription.
 */
typedef struct {
    int opts;                   /**< Subscription options. */
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /**< Event pipe number. */
    uint32_t priority;          /**< Priority of the subscription (automatically generated). */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_oper_get_xpath_sub_t;

/**
 * @brief Ext SHM module operational set of get subscriptions for given XPath.
 */
typedef struct {
    off_t xpath;                /**< XPath of the subscription (offset in ext SHM). */
    sr_mod_oper_get_sub_type_t sub_type; /**< Type of the subscription. */

    off_t xpath_subs;           /**< Subscriptions array of the given XPath (offset in ext SHM) */
    uint32_t xpath_sub_count;   /**< Number of subscriptions for given XPath */
} sr_mod_oper_get_sub_t;

/**
 * @brief Ext SHM module operational poll subscription.
 */
typedef struct {
    off_t xpath;                /**< XPath of the subscription (offset in ext SHM). */
    int opts;                   /**< Subscription options. */
    uint32_t sub_id;            /**< Unique subscription ID. */
    uint32_t evpipe_num;        /**< Event pipe number. */
    ATOMIC_T suspended;         /**< Whether the subscription is suspended. */
    sr_cid_t cid;               /**< Connection ID. */
} sr_mod_oper_poll_sub_t;

/**
 * @brief Ext SHM notification subscription.
 */
typedef struct {
    off_t xpath;                /**< XPath of the subscription (offset in ext SHM). */
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

/*
 * change data subscription SHM (multi)
 *
 * data SHM contents
 *
 * FOR SUBSCRIBERS:
 * event SR_SUB_EV_UPDATE, SR_SUB_EV_CHANGE, SR_SUB_EV_DONE, SR_SUB_EV_ABORT - char *user; char *diff_lyb - diff tree
 *
 * FOR ORIGINATOR (when subscriber_count is 0):
 * event SR_SUB_EV_SUCCESS - char *edit_lyb
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/*
 * notification subscription SHM (multi)
 *
 * data SHM contents
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_SUB_EV_NOTIF - char *user; time_t notif_timestamp; char *notif_lyb - notification
 */

/*
 * operational subscription SHM (generic)
 *
 * data SHM contents
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_SUB_EV_OPER - char *user; char *request_xpath; char *parent_lyb - existing data tree parent
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_SUB_EV_SUCCESS - char *data_lyb - parent with state data connected
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/*
 * RPC subscription SHM (generic)
 *
 * data SHM contents
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_SUB_EV_RPC - char *user; char *input_lyb - RPC/action with input
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_SUB_EV_SUCCESS - char *data_lyb - RPC/action with output
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/**
 * @brief Generic (single-subscriber) subscription SHM structure.
 */
typedef struct {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    sr_cid_t orig_cid;          /**< Event originator CID. */
    ATOMIC_T request_id;        /**< Request ID. */
    ATOMIC_T event;             /**< Event. */
} sr_sub_shm_t;

/**
 * @brief Multi-subscriber subscription SHM structure.
 */
typedef struct {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    sr_cid_t orig_cid;          /**< Event originator CID. */
    ATOMIC_T request_id;        /**< Request ID. */
    ATOMIC_T event;             /**< Event. */

    /* specific fields */
    ATOMIC_T priority;          /**< Priority of the subscriber. */
    uint32_t subscriber_count;  /**< Number of subscribers to process this event. */
} sr_multi_sub_shm_t;

#endif /* _SHM_TYPES_H */
