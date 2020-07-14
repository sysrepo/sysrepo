/**
 * @file shm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef _SHM_H
#define _SHM_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "common.h"

#define SR_MAIN_SHM_LOCK "sr_main_lock"     /**< Main SHM file lock name. */
#define SR_SHM_VER 2                        /**< Main and ext SHM version of their expected content structures. */

/**
 * Main SHM organization
 *
 * Except for main and ext SHM there are individual SHM segments for subscriptions and
 * running data files. These are not covered in the following text.
 *
 * There are 2 SHM segments, main SHM and ext SHM.
 *
 * Main SHM starts with ::sr_main_shm_t structure. Then is followed by all installed
 * modules, each with a ::sr_mod_t structure until the end of main SHM. All `off_t`
 * types in these structures are offset pointers to ext SHM.
 *
 * Ext shm starts with a `size_t` value representing the number of wasted
 * bytes in this SHM segment. It is followed by arrays and strings pointed to
 * by main SHM `off_t` pointers. First, there is the sysrepo connections state ::sr_conn_shm_t
 * meaning all currently running connections. Then, there is information from ::sr_mod_t
 * which includes names, dependencies, and subscriptions. Lastly, there are RPCs ::sr_rpc_t.
 * Also, any pointers in all the previous structures point, again, into ext SHM.
 */

/**
 * @brief Ext SHM module dependency type.
 */
typedef enum sr_mod_dep_type_e {
    SR_DEP_REF,         /**< Module reference (leafref, when, must). */
    SR_DEP_INSTID,      /**< Instance-identifier. */
} sr_mod_dep_type_t;

/**
 * @brief Ext SHM module data dependency.
 * (typedef sr_mod_data_dep_t)
 */
struct sr_mod_data_dep_s {
    sr_mod_dep_type_t type;     /**< Dependency type. */
    off_t module;               /**< Dependant module name. */
    off_t xpath;                /**< XPath of the node with the dependency. */
};

/**
 * @brief Ext SHM module operation dependency.
 */
typedef struct sr_mod_op_dep_s {
    off_t xpath;                /**< XPath of the node with the dependency. */
    off_t in_deps;              /**< Input operation dependencies (also notification). */
    uint16_t in_dep_count;      /**< Input dependency count. */
    off_t out_deps;             /**< Output operation dependencies. */
    uint16_t out_dep_count;     /**< Output dependency count. */
} sr_mod_op_dep_t;

/**
 * @brief Ext SHM module change subscriptions.
 */
typedef struct sr_mod_change_sub_s {
    off_t xpath;                /**< XPath of the subscription. */
    uint32_t priority;          /**< Subscription priority. */
    int opts;                   /**< Subscription options. */
    uint32_t evpipe_num;        /**< Event pipe number. */
} sr_mod_change_sub_t;

/**
 * @brief Ext SHM module operational subscription type.
 */
typedef enum sr_mod_oper_sub_type_e {
    SR_OPER_SUB_NONE = 0,         /**< Invalid type. */
    SR_OPER_SUB_STATE,            /**< Providing state data. */
    SR_OPER_SUB_CONFIG,           /**< Providing configuration data. */
    SR_OPER_SUB_MIXED,            /**< Providing both state and configuration data. */
} sr_mod_oper_sub_type_t;

/**
 * @brief Ext SHM module operational subscription.
 */
typedef struct sr_mod_oper_sub_s {
    off_t xpath;                /**< XPath of the subscription. */
    sr_mod_oper_sub_type_t sub_type;  /**< Type of the subscription. */
    int opts;                   /**< Subscription options. */
    uint32_t evpipe_num;        /** Event pipe number. */
} sr_mod_oper_sub_t;

/**
 * @brief Ext SHM notification subscription.
 */
typedef struct sr_mod_notif_sub_s {
    uint32_t evpipe_num;        /**< Event pipe number. */
} sr_mod_notif_sub_t;

#define SR_MOD_REPLAY_SUPPORT 0x01  /**< Flag for module with replay support. */

/**
 * @brief Main SHM module.
 * (typedef sr_mod_t)
 */
struct sr_mod_s {
    struct sr_mod_lock_s {
        sr_rwlock_t lock;       /**< Process-shared lock for accessing module instance data. */
        uint8_t write_locked;   /**< Whether module data are WRITE locked (lock itself may not be WRITE locked
                                     to allow data reading). */
        uint8_t ds_locked;      /**< Whether module data are datastore locked (NETCONF locks). */
        sr_sid_t sid;           /**< Session ID of the locking session (user is always NULL). */
        time_t ds_ts;           /**< Timestamp of the datastore lock. */
    } data_lock_info[SR_DS_COUNT]; /**< Module data lock information for each datastore. */
    sr_rwlock_t replay_lock;    /**< Process-shared lock for accessing stored notifications for replay. */
    uint32_t ver;               /**< Module data version (non-zero). */

    off_t name;                 /**< Module name. */
    char rev[11];               /**< Module revision. */
    uint8_t flags;              /**< Module flags. */

    off_t features;             /**< Array of enabled features (off_t *). */
    uint16_t feat_count;        /**< Number of enabled features. */
    off_t data_deps;            /**< Array of data dependencies. */
    uint16_t data_dep_count;    /**< Number of data dependencies. */
    off_t inv_data_deps;        /**< Array of inverse data dependencies (off_t *). */
    uint16_t inv_data_dep_count;    /**< Number of inverse data dependencies. */
    off_t op_deps;              /**< Array of operation dependencies. */
    uint16_t op_dep_count;      /**< Number of operation dependencies. */

    struct {
        off_t subs;             /**< Array of change subscriptions. */
        uint16_t sub_count;     /**< Number of change subscriptions. */
    } change_sub[SR_DS_COUNT];  /**< Change subscriptions for each datastore. */

    off_t oper_subs;            /**< Array of operational subscriptions. */
    uint16_t oper_sub_count;    /**< Number of operational subscriptions. */

    off_t notif_subs;           /**< Array of notification subscriptions. */
    uint16_t notif_sub_count;   /**< Number of notification subscriptions. */
};

/**
 * @brief Ext SHM RPC/action specific subscription.
 */
typedef struct sr_rpc_sub_s {
    off_t xpath;                /**< Full XPath of the RPC/action subscription. */
    uint32_t priority;          /**< Subscription priority. */
    int opts;                   /**< Subscription options. */
    uint32_t evpipe_num;        /**< Event pipe number. */
} sr_rpc_sub_t;

/**
 * @brief Ext SHM RPC/action subscriptions for a single operation.
 */
typedef struct sr_rpc_s {
    off_t op_path;              /**< Simple path of the RPC/action subscribed to. */
    off_t subs;                 /**< Array of RPC/action subscriptions. */
    uint16_t sub_count;         /**< Number of RPC/action subscriptions. */
} sr_rpc_t;

/**
 * @brief Lock mode.
 */
typedef enum sr_lock_mode_e {
    SR_LOCK_NONE = 0,           /**< Not locked. */
    SR_LOCK_READ,               /**< Read lock. */
    SR_LOCK_WRITE,              /**< Write lock. */
} sr_lock_mode_t;

/**
 * @brief Ext SHM connection state held lock.
 */
typedef struct sr_conn_shm_lock_s {
    sr_lock_mode_t mode;    /**< Held lock mode. */
    ATOMIC_T rcount;        /**< Number of recursive READ locks held. */
} sr_conn_shm_lock_t;

/**
 * @brief Ext SHM connection state.
 */
typedef struct sr_conn_shm_s {
    sr_conn_ctx_t *conn_ctx;    /**< Connection, process-specific pointer, do not access! */
    pid_t pid;                  /**< PID of process that created this connection. */

    sr_conn_shm_lock_t main_lock; /**< Held main SHM lock. */
    off_t mod_locks;            /**< Held SHM module locks, points to (sr_conn_state_lock_t (*)[SR_DS_COUNT]). */

    off_t evpipes;              /**< Array of event pipe numbers (uint32_t) of subscriptions on this connection. */
    uint16_t evpipe_count;      /**< Event pipe count. */
} sr_conn_shm_t;

/**
 * @brief Main SHM.
 */
typedef struct sr_main_shm_s {
    uint32_t shm_ver;           /**< Main and ext SHM version of all expected data stored in them. Is increased with
                                     every change of their structure content (ABI change). */
    sr_rwlock_t lock;           /**< Process-shared lock for accessing main and ext SHM. It is required only when
                                     accessing attributes that can be changed (subscriptions, replay support). */
    pthread_mutex_t lydmods_lock; /**< Process-shared lock for accessing sysrepo module data. */
    uint32_t mod_count;         /**< Number of installed modules stored after this structure. */

    off_t rpc_subs;             /**< Array of RPC/action subscriptions. */
    uint16_t rpc_sub_count;     /**< Number of RPC/action subscriptions. */

    ATOMIC_T new_sr_sid;        /**< SID for a new session. */
    ATOMIC_T new_evpipe_num;    /**< Event pipe number for a new subscription. */

    off_t conns;                /**< Array of existing connections (connection state). */
    uint16_t conn_count;        /**< Number of existing connections. */
} sr_main_shm_t;

/**
 * @brief Subscription event.
 */
typedef enum sr_sub_event_e {
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
    SR_SUB_EV_NOTIF,            /**< New notification event ready. */
} sr_sub_event_t;

/** Whether an event is one to be processed by the listeners (subscribers). */
#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_OPER) || (ev == SR_SUB_EV_RPC) \
        || (ev == SR_SUB_EV_NOTIF))

/** Whether an event is one to be processed by the originators. */
#define SR_IS_NOTIFY_EVENT(ev) ((ev == SR_SUB_EV_SUCCESS) || (ev == SR_SUB_EV_ERROR))

/**
 * @brief Generic (single-subscriber) subscription SHM structure.
 */
typedef struct sr_sub_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    uint32_t request_id;        /**< Request ID. */
    sr_sub_event_t event;       /**< Event. */
    sr_sid_t sid;               /**< Originator SID information. */
} sr_sub_shm_t;

/**
 * @brief Multi-subscriber subscription SHM structure.
 */
typedef struct sr_multi_sub_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    uint32_t request_id;        /**< Request ID. */
    sr_sub_event_t event;       /**< Event. */
    sr_sid_t sid;               /**< Originator SID information. */

    /* specific fields */
    uint32_t priority;          /**< Priority of the subscriber. */
    uint32_t subscriber_count;  /**< Number of subscribers to process this event. */
} sr_multi_sub_shm_t;
/*
 * change data subscription SHM (multi)
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_SUB_EV_UPDATE, SR_SUB_EV_CHANGE, SR_SUB_EV_DONE, SR_SUB_EV_ABORT - char *diff_lyb - diff tree
 *
 * FOR ORIGINATOR (when subscriber_count is 0)
 * followed by:
 * event SR_SUB_EV_SUCCESS - char *edit_lyb
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/*
 * notification subscription SHM (multi)
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_SUB_EV_NOTIF - time_t notif_timestamp; char *notif_lyb - notification
 */

/*
 * operational subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_SUB_EV_OPER - char *request_xpath; char *parent_lyb - existing data tree parent
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_SUB_EV_SUCCESS - char *data_lyb - parent with state data connected
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/*
 * RPC subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_SUB_EV_RPC - char *input_lyb - RPC/action with input
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_SUB_EV_SUCCESS - char *data_lyb - RPC/action with output
 * event SR_SUB_EV_ERROR - char *error_message; char *error_xpath
 */

/*
 * Main SHM low-level functions, use with caution with respect to locks, ...
 */

/**
 * @brief Check all used directories and create them if any are missing.
 *
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_check_dirs(void);

/**
 * @brief Create main SHM file lock used for creating main SHM.
 *
 * @param[out] shm_lock SHM create lock file descriptor.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_createlock_open(int *shm_lock);

/**
 * @brief Lock main SHM file lock. Note that the oldest standard file locks
 * are used, which lock for the whole process (every thread).
 *
 * @param[in] shm_lock Opened SHM create lock file descriptor.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_createlock(int shm_lock);

/**
 * @brief Unlock main SHM file lock.
 *
 * @param[in] shm_lock Locked SHM create lock file descriptor.
 */
void sr_shmmain_createunlock(int shm_lock);

/**
 * @brief Add connection into main SHM.
 * Main SHM lock is expected to be held.
 *
 * @param[in] conn Connection to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_add(sr_conn_ctx_t *conn);

/**
 * @brief Remove a connection from main SHM state.
 * Main SHM lock is expected to be held.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] conn Connection context to delete.
 * @param[in] pid Connection PID to delete.
 */
void sr_shmmain_conn_del(sr_main_shm_t *main_shm, char *ext_shm_addr, sr_conn_ctx_t *conn, pid_t pid);

/**
 * @brief Find a connection in main SHM.
 * Main SHM lock is expected to be held.
 *
 * @param[in] main_shm_addr Main SHM address.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] conn Connection context to find.
 * @param[in] pid Connection PID to find.
 * @return Matching connection state, NULL if not found.
 */
sr_conn_shm_t *sr_shmmain_conn_find(char *main_shm_addr, char *ext_shm_addr, sr_conn_ctx_t *conn, pid_t pid);

/**
 * @brief Add an event pipe into a connection in main SHM.
 * Main SHM lock is expected to be held.
 *
 * @param[in] conn Connection of the subscription.
 * @param[in] evpipe_num Event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_add_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num);

/**
 * @brief Remove and event pipe from a connection in main SHM.
 * Main SHM lock is expected to be held.
 *
 * @param[in] conn Connection of the subscription.
 * @param[in] evpipe_num Event pipe number.
 */
void sr_shmmain_conn_del_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num);

/**
 * @brief Initialize libyang context with only the internal sysrepo module.
 *
 * @param[out] ly_ctx Initialized context.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_ly_ctx_init(struct ly_ctx **ly_ctx);

/**
 * @brief Copy startup files into running files.
 *
 * @param[in] conn Connection to use.
 * @param[in] replace Whether replace any existing running data (standard copy-config) or copy data
 * only for modules that do not have any running data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_files_startup2running(sr_conn_ctx_t *conn, int replace);

/**
 * @brief Remap main SHM and add modules and their inverse dependencies into it.
 *
 * @param[in] conn Connection to use.
 * @param[in] sr_mod First module to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_add(sr_conn_ctx_t *conn, struct lyd_node *sr_mod);

/**
 * @brief Open (and init if needed) main SHM.
 *
 * @param[in,out] shm SHM structure to use.
 * @param[in,out] created Whether the main SHM was created. If NULL, do not create the memory if it does not exist.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_main_open(sr_shm_t *shm, int *created);

/**
 * @brief Open (and init if needed) Ext SHM.
 *
 * @param[in,out] shm SHM structure to use.
 * @param[in] zero Whether to zero (or init) Ext SHM.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_ext_open(sr_shm_t *shm, int zero);

/*
 * Main SHM common functions
 */

/**
 * @brief Find a specific main SHM module.
 *
 * Either name or name_off must be set.
 *
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] name String name of the module.
 * @param[in] name_off Ext SHM offset of the name (faster lookup, \p main_ext_shm_addr is not needed).
 * @return Main SHM module, NULL if not found.
 */
sr_mod_t *sr_shmmain_find_module(sr_shm_t *shm_main, char *ext_shm_addr, const char *name, off_t name_off);

/**
 * @brief Find a specific main SHM RPC.
 *
 * Either op_path or op_path_off must be set.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] op_path String name of the RPCmodule.
 * @param[in] op_path_off Ext SHM offset of the op_path (faster lookup, \p ext_shm_addr is not needed).
 * @return Main SHM RPC, NULL if not found.
 */
sr_rpc_t *sr_shmmain_find_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, const char *op_path, off_t op_path_off);

/**
 * @brief Lock main/ext SHM and its mapping and remap it if needed (it was changed). Also, store information
 * about held locks into SHM (a few function names are exceptions).
 *
 * !! Every API function that accesses ext SHM must call this function !!
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Whether to WRITE, READ or not lock main (actually ext) SHM.
 * @param[in] remap Whether to WRITE (ext SHM may be remapped) or READ (just protect from remapping) remap lock.
 * @param[in] func Caller function name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_lock_remap(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int remap, const char *func);

/**
 * @brief Unlock main SHM and update information about held locks in SHM. If remap was WRITE locked,
 * also defragment ext SHM as needed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Whether to WRITE, READ or not unlock main (actually ext) SHM.
 * @param[in] remap Whether to WRITE or READ remap unlock.
 * @param[in] func Caller function name.
 */
void sr_shmmain_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int remap, const char *func);

/**
 * @brief Add main SHM RPC/action subscription.
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM.
 * @param[in] shm_rpc_off SHM RPC offset.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscriptions options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_rpc_subscription_add(sr_shm_t *shm_ext, off_t shm_rpc_off, const char *xpath,
        uint32_t priority, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM RPC/action subscription.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] only_evpipe Whether to match only on \p evpipe_num.
 * @param[out] last_removed Whether this is the last RPC subscription that was removed.
 * @return 0 if removed, 1 if no matching found.
 */
int sr_shmmain_rpc_subscription_del(char *ext_shm_addr, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        uint32_t evpipe_num, int only_evpipe, int *last_removed);

/**
 * @brief Remove main SHM module RPC/action subscription and do a proper cleanup.
 * Calls ::sr_shmmain_rpc_subscription_del(), is a higher level wrapper.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] all_evpipe Whether to remove all subscriptions matching \p evpipe_num.
 * @param[out] last_removed Optional, set if the last subscription of the RPC was removed and hence also the RPC.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_rpc_subscription_stop(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath,
        uint32_t priority, uint32_t evpipe_num, int all_evpipe, int *last_removed);

/**
 * @brief Add an RPC/action into main SHM.
 * May remap ext SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] op_path Simple RPC/action path.
 * @param[out] shm_rpc_p If set, return the newly added RPC/action on success.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_add_rpc(sr_conn_ctx_t *conn, const char *op_path, sr_rpc_t **shm_rpc_p);

/**
 * @brief Remove an RPC/action from main SHM.
 *
 * Either op_path or op_path_off must be set.
 *
 * @param[in] main_shm Main SHM structure.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] op_path RPC/action path.
 * @param[in] op_path_off RPC/action path offset.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_del_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, const char *op_path, off_t op_path_off);

/**
 * @brief Change replay support of a module in main SHM.
 *
 * @param[in] shm_main Main SHM.
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] mod_name Module name. NUll for all the modules.
 * @param[in] replay_support Whether replay support should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_update_replay_support(sr_shm_t *shm_main, char *ext_shm_addr, const char *mod_name, int replay_support);

/**
 * @brief Check data file existence and owner/permissions of all the modules in main SHM.
 * Startup file must always exist, owner/permissions are read from it.
 * For running and operational, create them if they do not exist, then change their owner/permissions.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_check_data_files(sr_conn_ctx_t *conn);

/*
 * Main SHM module functions
 */

/**
 * @brief Collect required modules into mod info based on an edit.
 *
 * @param[in,out] mod_info Modified mod info.
 * @param[in] edit Edit to be applied.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_collect_edit(struct sr_mod_info_s *mod_info, const struct lyd_node *edit);

/**
 * @brief Collect required modules into mod info based on an XPath.
 *
 * @param[in,out] mod_info Modified mod info.
 * @param[in] xpath XPath to be evaluated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_collect_xpath(struct sr_mod_info_s *mod_info, const char *xpath);

/**
 * @brief Collect required modules into mod info based on a specific module.
 *
 * @param[in,out] mod_info Modified mod info.
 * @param[in] ly_mod Required module, all modules if not set.
 * @param[in] mod_req_deps What dependencies of the module are also needed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_collect_modules(struct sr_mod_info_s *mod_info, const struct lys_module *ly_mod,
        int mod_req_deps);

/**
 * @brief Collect required modules into mod info based on an operation data.
 *
 * @param[in,out] mod_info Modified mod info.
 * @param[in] op_path Path identifying the operation.
 * @param[in] op Operation data tree.
 * @param[in] output Whether this is the operation output or input.
 * @param[out] shm_deps Main SHM operation dependencies.
 * @param[out] shm_dep_count Operation dependency count.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_collect_op(struct sr_mod_info_s *mod_info, const char *op_path,
        const struct lyd_node *op, int output, sr_mod_data_dep_t **shm_deps, uint16_t *shm_dep_count);

/**
 * @brief READ lock all modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] upgradable Whether the lock will be upgraded to WRITE later. Used only for main DS of @p mod_info!
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradable, sr_sid_t sid);

/**
 * @brief WRITE lock all modules in mod info. Secondary DS modules, if any, are READ locked.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, sr_sid_t sid);

/**
 * @brief Upgrade READ lock on modules in mod info to WRITE lock.
 * Works only for upgradable READ lock, in which case there will only be one
 * thread waiting for WRITE lock.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, sr_sid_t sid);

/**
 * @brief Downgrade WRITE lock on modules in mod info to READ lock.
 * Works only for upgraded READ lock.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_wrlock_downgrade(struct sr_mod_info_s *mod_info, sr_sid_t sid);

/**
 * @brief Unlock mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] upgradable Whether we are unlocking normal READ lock or possibly upgraded to WRITE lock.
 */
void sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info, int upgradable);

/**
 * @brief Release any locks matching the provided SID.
 *
 * @param[in] conn Connection to use.
 * @param[in] sid Sysrepo session ID.
 */
void sr_shmmod_release_locks(sr_conn_ctx_t *conn, sr_sid_t sid);

/**
 * @brief Add main SHM module change subscription.
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] ds Datastore.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_change_subscription_add(sr_shm_t *shm_ext, sr_mod_t *shm_mod, const char *xpath,
        sr_datastore_t ds, uint32_t priority, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM module change subscription.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] ds Datastore.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] only_evpipe Whether to match only on \p evpipe_num.
 * @param[out] last_removed Whether this is the last module change subscription that was removed.
 * @return 0 if removed, 1 if no matching found.
 */
int sr_shmmod_change_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath, sr_datastore_t ds,
        uint32_t priority, int sub_opts, uint32_t evpipe_num, int only_evpipe, int *last_removed);

/**
 * @brief Remove main SHM module change subscription and do a proper cleanup.
 * Calls ::sr_shmmod_change_subscription_del(), is a higher level wrapper.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] ds Datastore.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] all_evpipe Whether to remove all subscriptions matching \p evpipe_num.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_change_subscription_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, const char *xpath,
        sr_datastore_t ds, uint32_t priority, int sub_opts, uint32_t evpipe_num, int all_evpipe);

/**
 * @brief Add main SHM module operational subscription.
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] sub_type Data-provide subscription type.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_oper_subscription_add(sr_shm_t *shm_ext, sr_mod_t *shm_mod, const char *xpath,
        sr_mod_oper_sub_type_t sub_type, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM module operational subscription.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] only_evpipe Whether to match only on \p evpipe_num.
 * @param[out] xpath_p Optionally return the xpath of the removed subscription.
 * @return 0 if removed, 1 if no matching found.
 */
int sr_shmmod_oper_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath, uint32_t evpipe_num,
        int only_evpipe, const char **xpath_p);

/**
 * @brief Remove main SHM module operational subscription and do a proper cleanup.
 * Calls ::sr_shmmod_oper_subscription_del(), is a higher level wrapper.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module.
 * @param[in] xpath Subscription XPath.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] all_evpipe Whether to remove all subscriptions matching \p evpipe_num.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_oper_subscription_stop(char *ext_shm_addr, sr_mod_t *shm_mod, const char *xpath,
        uint32_t evpipe_num, int all_evpipe);

/**
 * @brief Add main SHM module notification subscription.
 * May remap ext SHM!
 *
 * @param[in] shm_ext Ext SHM.
 * @param[in] shm_mod SHM module.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_notif_subscription_add(sr_shm_t *shm_ext, sr_mod_t *shm_mod, uint32_t evpipe_num);

/**
 * @brief Remove main SHM module notification subscription.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[out] last_removed Whether this is the last module notification subscription that was removed.
 * @return 0 if removed, 1 if no matching found.
 */
int sr_shmmod_notif_subscription_del(char *ext_shm_addr, sr_mod_t *shm_mod, uint32_t evpipe_num, int *last_removed);

/**
 * @brief Remove main SHM module notification subscription and do a proper cleanup.
 * Calls ::sr_shmmod_notif_subscription_del(), is a higher level wrapper.
 *
 * @param[in] ext_shm_addr Ext SHM address.
 * @param[in] shm_mod SHM module.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] all_evpipe Whether to remove all subscriptions matching \p evpipe_num.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_notif_subscription_stop(char *ext_shm_addr, sr_mod_t *shm_mod, uint32_t evpipe_num,
        int all_evpipe);

/**
 * @brief Remove all stored operational data of a connection.
 *
 * @param[in] conn Connection to use.
 * @param[in] del_conn Connection whose data to remove.
 * @param[in] del_pid PID of \p del_conn.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_oper_stored_del_conn(sr_conn_ctx_t *conn, sr_conn_ctx_t *del_conn, pid_t del_pid);

/*
 * Subscription SHM functions.
 */

/**
 * @brief Open and map a subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[out] shm Mapped SHM.
 * @param[in] shm_struct_size Size of the used subscription SHM structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm,
        size_t shm_struct_size);

/**
 * @brief Write into a subscriber event pipe to notify it there is a new event.
 *
 * @param[in] evpipe_num Subscriber event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notify_evpipe(uint32_t evpipe_num);

/**
 * @brief Notify about (generate) a change "update" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] update_edit Updated edit from subscribers, if any.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_update(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms,
        struct lyd_node **update_edit, sr_error_info_t **cb_err_info);

/**
 * @brief Clear a change event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] ev Event to clear.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_clear(struct sr_mod_info_s *mod_info, sr_sub_event_t ev);

/**
 * @brief Notify about (generate) a change "change" event.
 * Main SHM lock(0,0,0) must be held and this function may temporarily unlock it!
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms,
        sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) a change "done" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_done(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) a change "abort" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_abort(struct sr_mod_info_s *mod_info, sr_sid_t sid, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) an operational event.
 *
 * @param[in] ly_mod Module to use.
 * @param[in] xpath Subscription XPath.
 * @param[in] request_xpath Requested XPath.
 * @param[in] parent Existing parent to append the data to.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[out] data Data provided by the subscriber.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_notify(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath,
        const struct lyd_node *parent, sr_sid_t sid, uint32_t evpipe_num, uint32_t timeout_ms, struct lyd_node **data,
        sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action event.
 * Main SHM lock(0,0,0) must be held and this function may temporarily unlock it!
 *
 * @param[in] conn Connection to use.
 * @param[in] op_path Path identifying the RPC/action.
 * @param[in] input Operation input tree.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[in,out] request_id Generated request ID, set to 0 when passing.
 * @param[out] output Operation output returned by the last subscriber on success.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify(sr_conn_ctx_t *conn, const char *op_path, const struct lyd_node *input,
        sr_sid_t sid, uint32_t timeout_ms, uint32_t *request_id, struct lyd_node **output, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action abort event.
 *
 * @param[in] conn Connection to use.
 * @param[in] op_path Path identifying the RPC/action.
 * @param[in] input Operation input tree.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] request_id Generated request ID from previous event.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify_abort(sr_conn_ctx_t *conn, const char *op_path, const struct lyd_node *input,
        sr_sid_t sid, uint32_t request_id);

/**
 * @brief Notify about (generate) a notification event.
 *
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] notif_sub_evpipe_nums Array of subscribers event pipe numbers.
 * @param[in] notif_sub_count Number of subscribers.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_notify(const struct lyd_node *notif, time_t notif_ts, sr_sid_t sid,
        uint32_t *notif_sub_evpipe_nums, uint32_t notif_sub_count);

/**
 * @brief Process all module change events, if any.
 *
 * @param[in] change_subs Module change subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_listen_process_module_events(struct modsub_change_s *change_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all module operational events, if any.
 *
 * @param[in] oper_subs Module operational subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_listen_process_module_events(struct modsub_oper_s *oper_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all RPC/action events for one RPC/action, if any.
 *
 * @param[in] rpc_sub RPC/action subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_listen_process_rpc_events(struct opsub_rpc_s *rpc_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all module notification events, if any.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_process_module_events(struct modsub_notif_s *notif_subs, sr_conn_ctx_t *conn);

/**
 * @brief Check whether there is a pending replay or stop time elapsed for a module notification subscription.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @return 0 if no such events occured, non-zero if they did.
 */
int sr_shmsub_notif_listen_module_has_replay_or_stop(struct modsub_notif_s *notif_subs);

/**
 * @brief Get nearest stop time of a subscription, if any.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in,out] stop_time_in Nearest stop time of a subscription, if none, left unmodified.
 */
void sr_shmsub_notif_listen_module_get_stop_time_in(struct modsub_notif_s *notif_subs, time_t *stop_time_in);

/**
 * @brief Check notification subscriptions stop time and finish the subscription if it has elapsed.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] subs Subscriptions structure.
 * @param[out] module_finished Whether the last module notification subscription was finished.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_stop_time(struct modsub_notif_s *notif_subs,
        sr_subscription_ctx_t *subs, int *module_finished);

/**
 * @brief Check notification subscription replay state and perform it if requested.
 * May remap ext SHM!
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] subs Subscriptions structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_replay(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subs);

/**
 * @brief Listener handler thread of all subscriptions.
 *
 * @param[in] arg Pointer to the subscription structure.
 * @return Always NULL.
 */
void *sr_shmsub_listen_thread(void *arg);

#endif
