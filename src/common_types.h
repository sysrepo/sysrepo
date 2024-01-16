/**
 * @file common_types.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common types header
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

#ifndef _COMMON_TYPES_H
#define _COMMON_TYPES_H

#define _GNU_SOURCE

#include <pthread.h>
#include <time.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "sysrepo_types.h"

/**
 * @brief Generic shared memory information structure.
 */
typedef struct {
    int fd;                         /**< Shared memory file desriptor. */
    size_t size;                    /**< Shared memory mapping current size. */
    char *addr;                     /**< Shared memory mapping address. */
} sr_shm_t;

/**
 * @brief Lock mode.
 */
typedef enum {
    SR_LOCK_NONE = 0,           /**< Not locked. */
    SR_LOCK_READ,               /**< Read lock. */
    SR_LOCK_READ_UPGR,          /**< Read lock with the upgrade capability. */
    SR_LOCK_WRITE,              /**< Write lock. */
    SR_LOCK_WRITE_URGE          /**< Write lock with priority forcing next readers to wait. */
} sr_lock_mode_t;

/** maximum number of system-wide concurrent connection owners of a read lock */
#define SR_RWLOCK_READ_LIMIT 16

/**
 * @brief Sysrepo read-write lock.
 */
typedef struct {
    pthread_mutex_t mutex;          /**< Lock mutex. */
    sr_cond_t cond;                 /**< Lock condition variable. */

    sr_cid_t readers[SR_RWLOCK_READ_LIMIT]; /**< CIDs of all READ lock owners (including READ-UPGR), 0s otherwise. */
    uint8_t read_count[SR_RWLOCK_READ_LIMIT];   /**< Number of recursive read locks of the connection in readers. */
    sr_cid_t upgr;                  /**< CID of the READ-UPGR lock owner if locked, 0 otherwise. */
    sr_cid_t writer;                /**< CID of the WRITE lock owner if locked, can be set if an WRITE-URGE lock
                                         is being waited on, 0 otherwise. */
} sr_rwlock_t;

/**
 * @brief Subscription event.
 */
typedef enum {
    SR_SUB_EV_NONE = 0,         /**< No event. */
    SR_SUB_EV_SUCCESS,          /**< Event processed successfully by subscribers. */
    SR_SUB_EV_ERROR,            /**< Event failed to be processed by a subscriber. */

    SR_SUB_EV_UPDATE,           /**< New update event ready. */
    SR_SUB_EV_CHANGE,           /**< New change event ready. */
    SR_SUB_EV_DONE,             /**< New done event ready. */
    SR_SUB_EV_ABORT,            /**< New abort event ready. */
    SR_SUB_EV_ENABLED,          /**< New enabled event ready. */
    SR_SUB_EV_OPER,             /**< New operational event ready. */
    SR_SUB_EV_RPC,              /**< New RPC/action event ready. */
    SR_SUB_EV_NOTIF             /**< New notification event ready. */
} sr_sub_event_t;

/**
 * @brief XPath expression atoms.
 */
typedef struct {
    struct {
        char **atoms;
        uint32_t atom_count;
    } *unions;
    uint32_t union_count;
} sr_xp_atoms_t;

/*
 * Private definitions of public declarations
 */

/**
 * @brief Sysrepo connection.
 */
struct sr_conn_ctx_s {
    struct ly_ctx *ly_ctx;          /**< Libyang context, also available to user. */
    uint32_t content_id;            /**< Connection context content id. */
    sr_conn_options_t opts;         /**< Connection options. */

    pthread_mutex_t ptr_lock;       /**< Session-shared lock for accessing pointers to sessions. */
    sr_session_ctx_t **sessions;    /**< Array of sessions for this connection. */
    uint32_t session_count;         /**< Session count. */
    sr_cid_t cid;                   /**< Globally unique connection ID */
    sr_rwlock_t ly_ext_data_lock;   /**< Session-shared lock for accessing ly_ext_data. */
    struct lyd_node *ly_ext_data;   /**< Data for LY ext data callback set for ly_ctx. */

    int create_lock;                /**< Process-shared file lock for creating main/mod/ext SHM. */
    sr_shm_t main_shm;              /**< Main SHM structure. */
    sr_rwlock_t mod_remap_lock;     /**< Session-shared lock only for remapping mod SHM. */
    sr_shm_t mod_shm;               /**< Mod SHM structure. */
    sr_rwlock_t ext_remap_lock;     /**< Session-shared lock only for remapping ext SHM. */
    sr_shm_t ext_shm;               /**< External SHM structure. */

    struct sr_ds_handle_s {
        void *dl_handle;            /**< Handle from dlopen(3) call. */
        const struct srplg_ds_s *plugin;    /**< Datastore plugin. */
        int init;                   /**< Whether the plugin is initialized. */
        void *plg_data;             /**< Plugin connection data. */
    } *ds_handles;                  /**< Datastore implementation handles. */
    uint32_t ds_handle_count;       /**< Datastore implementaion handle count. */

    struct lyd_node *run_cache_data;    /**< Cached running data of all the modules. */
    struct sr_run_cache_s {
        const struct lys_module *mod;   /**< Cached libyang module. */
        uint32_t id;                    /**< Cached module data ID. */
    } *run_cache_mods;
    uint32_t run_cache_mod_count;
    sr_rwlock_t run_cache_lock;     /**< Session-shared lock for accessing running data cache. */

    struct sr_ntf_handle_s {
        void *dl_handle;            /**< Handle from dlopen(3) call. */
        const struct srplg_ntf_s *plugin;   /**< Notification plugin. */
    } *ntf_handles;                 /**< Notification implementation handles. */
    uint32_t ntf_handle_count;      /**< Notification implementaion handle count. */

    struct sr_oper_poll_cache_s {
        uint32_t sub_id;            /**< Operational poll subscription ID. */
        char *module_name;          /**< Operational poll subscription module name. */
        char *path;                 /**< Operational poll/get subscription path. */

        sr_rwlock_t data_lock;      /**< Lock for accessing the data and timestamp. */
        struct lyd_node *data;      /**< Cached data of a single operational get subscription. */
        struct timespec timestamp;  /**< Timestamp of the cached operational data. */
    } *oper_caches;                 /**< Operational get subscription data caches. */
    uint32_t oper_cache_count;      /**< Operational get subscription data cache count. */
    sr_rwlock_t oper_cache_lock;    /**< Operational get subscription data cache lock. */

    char **oper_push_mods;          /**< Modules whose pushed oper data were modified by this connection. */
    uint32_t oper_push_mod_count;   /**< Count of modules with modified push oper data. */
};

/**
 * @brief Sysrepo session.
 */
struct sr_session_ctx_s {
    sr_conn_ctx_t *conn;            /**< Connection used for creating this session. */
    sr_datastore_t ds;              /**< Datastore of the session. */
    uint32_t sid;                   /**< Session ID. */
    char *user;                     /**< Session (system) user. */
    char *nacm_user;                /**< Optional NACM user. If set, NACM is applied. */
    sr_error_info_t *err_info;      /**< Session error information. */

    char *orig_name;                /**< Originator name used for all events sent on this session. */
    void *orig_data;                /**< Originator data used for all events sent on this session. */

    sr_sub_event_t ev;              /**< Event of a callback session. ::SR_SUB_EV_NONE for standard user sessions. */

    struct {
        char *orig_name;            /**< Set originator name by the event originator. */
        void *orig_data;            /**< Set originator data by the event originator. */
    } ev_data;                      /**< Event data from the originator. Valid only if ev is not ::SR_SUB_EV_NONE. */
    struct {
        char *message;              /**< Event error message. */
        char *format;               /**< Event error data format. */
        void *data;                 /**< Event error data. */
    } ev_error;                     /**< Event error for the originator. Valid only if ev is not ::SR_SUB_EV_NONE. */

    pthread_mutex_t ptr_lock;       /**< Lock for accessing pointers to subscriptions. */
    sr_subscription_ctx_t **subscriptions;  /**< Array of subscriptions of this session. */
    uint32_t subscription_count;    /**< Subscription count. */

    struct {
        sr_data_t *edit;            /**< Prepared edit data tree. */
        struct lyd_node *diff;      /**< Diff data tree, used for module change iterator. */
    } dt[SR_DS_COUNT];              /**< Session-exclusive prepared changes. */

    struct sr_sess_notif_buf {
        int thread_running;         /**< Flag whether the notification buffering thread of this session is running. */
        pthread_t tid;              /**< Thread ID of the thread. */
        sr_rwlock_t lock;           /**< Lock for accessing thread_running and the notification buffer
                                         (READ-lock is not used). */
        struct sr_sess_notif_buf_node {
            struct lyd_node *notif;     /**< Buffered notification to be stored. */
            struct timespec notif_ts;   /**< Buffered notification timestamp. */
            struct sr_sess_notif_buf_node *next;    /**< Next stored notification buffer node. */
        } *first;                   /**< First stored notification buffer node. */
        struct sr_sess_notif_buf_node *last;    /**< Last stored notification buffer node. */
    } notif_buf;                    /**< Notification buffering attributes. */
};

/**
 * @brief Sysrepo subscription.
 */
struct sr_subscription_ctx_s {
    sr_conn_ctx_t *conn;            /**< Connection of the subscription. */
    uint32_t evpipe_num;            /**< Event pipe number of this subscription structure. */
    int evpipe;                     /**< Event pipe opened for reading. */
    ATOMIC_T thread_running;        /**< Flag whether the thread handling this subscription is running. */
    pthread_t tid;                  /**< Thread ID of the handler thread. */
    sr_rwlock_t subs_lock;          /**< Session-shared lock for accessing the subscriptions. */
    uint32_t last_sub_id;           /**< Subscription ID of the last created subscription. */

    struct modsub_change_s {
        char *module_name;          /**< Module of the subscriptions. */
        sr_datastore_t ds;          /**< Datastore of the subscriptions. */
        struct modsub_changesub_s {
            uint32_t sub_id;        /**< Unique subscription ID. */
            char *xpath;            /**< Subscription XPath. */
            uint32_t priority;      /**< Subscription priority. */
            sr_subscr_options_t opts;   /**< Subscription options. */
            sr_module_change_cb cb; /**< Subscription callback. */
            void *private_data;     /**< Subscription callback private data. */
            sr_session_ctx_t *sess; /**< Subscription session. */
            ATOMIC_T filtered_out;  /**< Number of notifications that were filtered out. */

            ATOMIC_T request_id;    /**< Request ID of the last processed request. */
            ATOMIC_T event;         /**< Type of the last processed event. */
        } *subs;                    /**< Configuration change subscriptions for each XPath. */
        uint32_t sub_count;         /**< Configuration change module XPath subscription count. */

        sr_shm_t sub_shm;           /**< Subscription SHM. */
    } *change_subs;                 /**< Change subscriptions for each module. */
    uint32_t change_sub_count;      /**< Change module subscription count. */

    struct modsub_operget_s {
        char *module_name;          /**< Module of the subscriptions. */
        struct modsub_opergetsub_s {
            uint32_t sub_id;        /**< Unique subscription ID. */
            char *path;             /**< Subscription path. */
            uint32_t priority;      /**< Subscription priority for one XPath */
            sr_oper_get_items_cb cb;    /**< Subscription callback. */
            void *private_data;     /**< Subscription callback private data. */
            sr_session_ctx_t *sess; /**< Subscription session. */

            ATOMIC_T request_id;    /**< Request ID of the last processed request. */
            sr_shm_t sub_shm;       /**< Subscription SHM. */
        } *subs;                    /**< Operational subscriptions for each XPath. */
        uint32_t sub_count;         /**< Operational module XPath subscription count. */
    } *oper_get_subs;               /**< Operational get subscriptions for each module. */
    uint32_t oper_get_sub_count;    /**< Operational get module subscription count. */

    struct modsub_operpoll_s {
        char *module_name;          /**< Module of the subscriptions. */
        struct modsub_operpollsub_s {
            uint32_t sub_id;        /**< Unique subscription ID. */
            char *path;             /**< Subscription path. */
            uint32_t valid_ms;      /**< Cached operational data validity interval in ms. */
            sr_subscr_options_t opts;   /**< Subscription options. */
            sr_session_ctx_t *sess; /**< Subscription session. */
        } *subs;                    /**< Operational subscriptions for each XPath. */
        uint32_t sub_count;         /**< Operational module XPath subscription count. */
    } *oper_poll_subs;              /**< Operational poll subscriptions for each module. */
    uint32_t oper_poll_sub_count;   /**< Operational poll module subscription count. */

    struct modsub_notif_s {
        char *module_name;          /**< Module of the subscriptions. */
        struct modsub_notifsub_s {
            uint32_t sub_id;        /**< Unique subscription ID. */
            char *xpath;            /**< Subscription XPath. */
            struct timespec listen_since_mono;  /**< Monotonic timestamp of the subscription listening for real-time notifications. */
            struct timespec listen_since_real;  /**< Realtime timestamp of the subscription listening for real-time notifications. */
            struct timespec start_time; /**< Subscription start time. */
            int replayed;           /**< Flag whether the subscription replay is finished. */
            struct timespec stop_time;  /**< Subscription stop time. */
            sr_event_notif_cb cb;   /**< Subscription value callback. */
            sr_event_notif_tree_cb tree_cb; /**< Subscription tree callback. */
            void *private_data;     /**< Subscription callback private data. */
            sr_session_ctx_t *sess; /**< Subscription session. */
            ATOMIC_T filtered_out;  /**< Number of notifications that were filtered out. */
        } *subs;                    /**< Notification subscriptions for each XPath. */
        uint32_t sub_count;         /**< Notification module XPath subscription count. */

        ATOMIC_T request_id;        /**< Request ID of the last processed request. */
        sr_shm_t sub_shm;           /**< Subscription SHM. */
    } *notif_subs;                  /**< Notification subscriptions for each module. */
    uint32_t notif_sub_count;       /**< Notification module subscription count. */

    struct opsub_rpc_s {
        char *path;                 /**< Subscription RPC/action path. */
        int is_ext;                 /**< Whether the RPC/action is in an extension or not. */
        struct opsub_rpcsub_s {
            uint32_t sub_id;        /**< Unique subscription ID. */
            char *xpath;            /**< Subscription XPath. */
            uint32_t priority;      /**< Subscription priority. */
            sr_rpc_cb cb;           /**< Subscription value callback. */
            sr_rpc_tree_cb tree_cb; /**< Subscription tree callback. */
            void *private_data;     /**< Subscription callback private data. */
            sr_session_ctx_t *sess; /**< Subscription session. */

            ATOMIC_T request_id;    /**< Request ID of the last processed request. */
            ATOMIC_T event;         /**< Type of the last processed event. */
        } *subs;                    /**< RPC/action subscription for each XPath. */
        uint32_t sub_count;         /**< RPC/action XPath subscription count. */

        sr_shm_t sub_shm;           /**< Subscription SHM. */
    } *rpc_subs;                    /**< RPC/action subscriptions for each operation. */
    uint32_t rpc_sub_count;         /**< RPC/action operation subscription count. */
};

/**
 * @brief Change iterator.
 */
struct sr_change_iter_s {
    struct lyd_node *diff;          /**< Optional copied diff that set items point into. */
    struct ly_set *set;             /**< Set of all the selected diff nodes. */
    uint32_t idx;                   /**< Index of the next change. */
};

/**
 * @brief Callback called for each recovered owner of a lock.
 *
 * @param[in] mode Dead owner lock mode.
 * @param[in] cid Dead owner connection ID.
 * @param[in] data Arbitrary user data.
 */
typedef void (*sr_lock_recover_cb)(sr_lock_mode_t mode, sr_cid_t cid, void *data);

/**
 * @brief Internal DS plugin "JSON DS file".
 */
extern const struct srplg_ds_s srpds_json;

/**
 * @brief Internal notif plugin "JSON notif".
 */
extern const struct srplg_ntf_s srpntf_json;

#endif /* _COMMON_TYPES_H */
