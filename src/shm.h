/**
 * @file shm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#ifndef _SHM_H
#define _SHM_H

#include <stdint.h>
#include <pthread.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "common.h"

#define SR_MAIN_SHM "/sr_main"              /**< Main SHM name. */
#define SR_MAIN_EXT_SHM "/sr_ext_main"      /**< Main external SHM name. */
#define SR_MAIN_SHM_LOCK "sr_main_lock"     /**< Main SHM file lock name. */

/**
 * @brief Main ext SHM module dependency type.
 */
typedef enum sr_mod_dep_type_e {
    SR_DEP_REF,         /**< Module reference (leafref, when, must). */
    SR_DEP_INSTID,      /**< Instance-identifier. */
} sr_mod_dep_type_t;

/**
 * @brief Main ext SHM module data dependency.
 * (typedef sr_mod_data_dep_t)
 */
struct sr_mod_data_dep_s {
    sr_mod_dep_type_t type;     /**< Dependency type. */
    off_t module;               /**< Dependant module name. */
    off_t xpath;                /**< XPath of the node with the dependency. */
};

/**
 * @brief Main ext SHM module operation dependency.
 */
typedef struct sr_mod_op_dep_s {
    off_t xpath;                /**< XPath of the node with the dependency. */
    off_t in_deps;              /**< Input operation dependencies (also notification). */
    uint16_t in_dep_count;      /**< Input dependency count. */
    off_t out_deps;             /**< Output operation dependencies. */
    uint16_t out_dep_count;     /**< Output dependency count. */
} sr_mod_op_dep_t;

/**
 * @brief Main ext SHM module configuration subscriptions.
 */
typedef struct sr_mod_conf_sub_s {
    off_t xpath;                /**< XPath of the subscription. */
    uint32_t priority;          /**< Subscription priority. */
    int opts;                   /**< Subscription options. */
    uint32_t evpipe_num;        /**< Event pipe number. */
} sr_mod_conf_sub_t;

/**
 * @brief Main ext SHM module operational subscription type.
 */
typedef enum sr_mod_oper_sub_type_e {
    SR_OPER_SUB_NONE = 0,         /**< Invalid type. */
    SR_OPER_SUB_STATE,            /**< Providing state data. */
    SR_OPER_SUB_CONFIG,           /**< Providing configuration data. */
    SR_OPER_SUB_MIXED,            /**< Providing both state and configuration data. */
} sr_mod_oper_sub_type_t;

/**
 * @brief Main ext SHM module operational subscription.
 */
typedef struct sr_mod_oper_sub_s {
    off_t xpath;                /**< XPath of the subscription. */
    sr_mod_oper_sub_type_t sub_type;  /**< Type of the subscription. */
    uint32_t evpipe_num;        /** Event pipe number. */
} sr_mod_oper_sub_t;

/**
 * @brief Main ext SHM RPC/action subscription.
 */
typedef struct sr_mod_rpc_sub_s {
    off_t xpath;                /**< XPath of the RPC/action subscribed to. */
    uint32_t evpipe_num;        /**< Event pipe number. */
} sr_mod_rpc_sub_t;

/**
 * @brief Main ext SHM notification subscription.
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
        sr_rwlock_t lock;       /**< Process-shared lock for accessing module data. */
        uint8_t write_locked;   /**< Whether module data are WRITE locked (lock may not be WRITE locked to allow data reading). */
        uint8_t ds_locked;      /**< Whether module data are datastore locked (NETCONF locks). */
        sr_sid_t sid;           /**< Session ID of the locking session (user is always NULL). */
        time_t ds_ts;           /**< Timestamp of the datastore lock. */
    } data_lock_info[SR_WRITABLE_DS_COUNT]; /**< Module data lock information for each datastore. */
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
        off_t subs;             /**< Array of configuration subscriptions. */
        uint16_t sub_count;     /**< Number of configuration subscriptions. */
    } conf_sub[SR_WRITABLE_DS_COUNT];   /**< Configuration subscriptions for each datastore. */

    off_t oper_subs;            /**< Array of operational subscriptions. */
    uint16_t oper_sub_count;    /**< Number of operational subscriptions. */

    off_t rpc_subs;             /**< Array of RPC/action subscriptions. */
    uint16_t rpc_sub_count;     /**< Number of RPC/action subscriptions. */

    off_t notif_subs;           /**< Array of notification subscriptions. */
    uint16_t notif_sub_count;   /**< Number of notification subscriptions. */
};

/**
 * @brief Connection state.
 */
typedef struct sr_conn_state_s {
    sr_conn_ctx_t *conn_ctx;    /**< Connection, process-specific pointer, do not access! */
    pid_t pid;                  /**< PID of process that created this connection. */
    off_t evpipes;              /**< Array of event pipes of subscriptions on this connection. */
    uint32_t evpipe_count;      /**< Event pipe count. */
} sr_conn_state_t;

/**
 * @brief Main SHM.
 */
typedef struct sr_main_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing main (ext) SHM. */
    uint32_t ver;               /**< Main SHM version (installed module set version). */
    ATOMIC_T new_sr_sid;        /**< SID for a new session. */
    ATOMIC_T new_evpipe_num;    /**< Event pipe number for a new subscription. */
    struct {
        off_t conns;            /**< Array of existing connections. */
        uint32_t conn_count;    /**< Number of existing connections. */
    } conn_state;               /**< Information about connection state. */
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
    SR_SUB_EV_OPER,             /**< New operational event ready. */
    SR_SUB_EV_RPC,              /**< New RPC/action event ready. */
    SR_SUB_EV_NOTIF,            /**< New notification event ready. */
} sr_sub_event_t;

/** Whether an event is one to be processed by the listeners (subscribers). */
#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_OPER) || (ev == SR_SUB_EV_RPC) || (ev == SR_SUB_EV_NOTIF))

/** Whether an event is one to be processed by the originators. */
#define SR_IS_NOTIFY_EVENT(ev) ((ev == SR_SUB_EV_SUCCESS) || (ev == SR_SUB_EV_ERROR))

/**
 * @brief Generic (single-subscriber) subscription SHM structure.
 */
typedef struct sr_sub_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    uint32_t event_id;          /**< Event ID. */
    sr_sub_event_t event;       /**< Event. */
    sr_sid_t sid;               /**< Originator SID information. */
} sr_sub_shm_t;

/**
 * @brief Multi-subscriber subscription SHM structure.
 */
typedef struct sr_multi_sub_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing the SHM structure. */

    uint32_t event_id;          /**< Event ID. */
    sr_sub_event_t event;       /**< Event. */
    sr_sid_t sid;               /**< Originator SID information. */

    /* specific fields */
    uint32_t priority;          /**< Priority of the subscriber. */
    uint32_t subscriber_count;  /**< Number of subscribers to process this event. */
} sr_multi_sub_shm_t;
/*
 * config data subscription SHM (multi)
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
 * event SR_SUB_EV_OPER - char *parent_lyb - existing data tree parent
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
 * @brief Debug print the contents of main ext SHM.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] main_ext_shm_addr Main ext SHM mapping address.
 * @param[in] main_ext_shm_size Main ext SHM mapping size.
 */
void sr_shmmain_ext_print(sr_shm_t *main_shm, char *main_ext_shm_addr, size_t main_ext_shm_size);

/**
 * @brief Defragment main ext SHM.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] main_ext_shm Main ext SHM.
 * @param[out] defrag_ext_buf Defragmented main ext SHM memory copy.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_ext_defrag(sr_shm_t *main_shm, sr_shm_t *main_ext_shm, char **defrag_ext_buf);

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
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_createlock(sr_conn_ctx_t *conn);

/**
 * @brief Unlock main SHM file lock.
 *
 * @param[in] conn Connection to use.
 */
void sr_shmmain_createunlock(sr_conn_ctx_t *conn);

/**
 * @brief Add connection into main SHM state.
 *
 * @param[in] conn Connection to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_state_add_conn(sr_conn_ctx_t *conn);

/**
 * @brief Remove a connection from main SHM state.
 *
 * @param[in] conn Connection to delete.
 */
void sr_shmmain_state_del_conn(sr_conn_ctx_t *conn);

/**
 * @brief Add an event pipe into main SHM state.
 * Main SHM lock is expected to be held.
 *
 * @param[in] conn Connection of the subscription.
 * @param[in] evpipe_num Event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_state_add_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num);

/**
 * @brief Remove and event pipe from main SHM state.
 * Main SHM lock is expected to be held.
 *
 * @param[in] conn Connection of the subscription.
 * @param[in] evpipe_num Event pipe number.
 */
void sr_shmmain_state_del_evpipe(sr_conn_ctx_t *conn, uint32_t evpipe_num);

/**
 * @brief Parse internal sysrepo module data.
 *
 * @param[in] conn Connection to use.
 * @param[in] apply_sched Whether to apply scheduled changes stored in these data.
 * @param[out] sr_mods_p Sysrepo modules data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_ly_int_data_parse(sr_conn_ctx_t *conn, int apply_sched, struct lyd_node **sr_mods_p);

/**
 * @brief Create main SHM.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_create(sr_conn_ctx_t *conn);

/**
 * @brief Open main SHM.
 *
 * @param[in] conn Connection to use.
 * @param[out] nonexistent Whether main SHM failed to opened because it does not exist.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_open(sr_conn_ctx_t *conn, int *nonexistent);

/*
 * Main SHM common functions
 */

/**
 * @brief Find a specific main SHM module.
 *
 * Either of name or name_off must be set.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] main_ext_shm_addr Main ext SHM address.
 * @param[in] name String name of the module.
 * @param[in] name_off Main ext SHM offset of the name (faster lookup, \p main_ext_shm_addr is not needed).
 * @return Main SHM module, NULL if not found.
 */
sr_mod_t *sr_shmmain_find_module(sr_shm_t *main_shm, char *main_ext_shm_addr, const char *name, off_t name_off);

/**
 * @brief Lock main SHM and its mapping and remap it if needed (it was changed).
 *
 * @param[in] conn Connection to use.
 * @param[in] wr Whether to WRITE or READ lock main SHM.
 * @param[in] remap Whether to WRITE (main SHM may be remapped) or READ (just protect from remapping) remap lock.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int remap);

/**
 * @brief Unlock main SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] wr Whether to WRITE or READ unlock main SHM.
 * @param[in] remap Whether to WRITE or READ remap unlock.
 */
void sr_shmmain_unlock(sr_conn_ctx_t *conn, int wr, int remap);

/**
 * @brief Add a module with any imports into main SHM and persistent internal data.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod Module to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_add_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *ly_mod);

/**
 * @brief Change replay support of a module in main SHM and persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] replay_support Whether replay support should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_update_replay_support(sr_conn_ctx_t *conn, const char *mod_name, int replay_support);

/**
 * @brief Unschedule module deletion from persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod Module that is scheduled to be deleted.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_unsched_del_module_with_imps(sr_conn_ctx_t *conn, const struct lys_module *ly_mod);

/**
 * @brief Schedule module deletion to persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name to delete.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_deferred_del_module(sr_conn_ctx_t *conn, const char *mod_name);

/**
 * @brief Schedule module update to persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_upd_mod Update module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_deferred_upd_module(sr_conn_ctx_t *conn, const struct lys_module *ly_upd_mod);

/**
 * @brief Unschedule module update from persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name to be updated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_unsched_upd_module(sr_conn_ctx_t *conn, const char *mod_name);

/**
 * @brief Schedule a feature change (enable/disable) into persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] feat_name Feature name.
 * @param[in] to_enable Whether the feature should be enabled or disabled.
 * @param[in] is_enabled Whether the feature is currently enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_deferred_change_feature(sr_conn_ctx_t *conn, const char *mod_name, const char *feat_name,
        int to_enable, int is_enabled);

/*
 * Main SHM module functions
 */

/**
 * @brief Collect required modules into mod info based on an edit.
 *
 * @param[in] conn Connection to use.
 * @param[in] edit Edit to be applied.
 * @param[in] ds Datastore.
 * @param[in,out] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_edit(sr_conn_ctx_t *conn, const struct lyd_node *edit, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules into mod info based on an XPath.
 *
 * @param[in] conn Connection to use.
 * @param[in] xpath XPath to be evaluated.
 * @param[in] ds Datastore.
 * @param[in,out] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_xpath(sr_conn_ctx_t *conn, const char *xpath, sr_datastore_t ds,
        struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules into mod info based on a specific module.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod Required module, all modules if not set.
 * @param[in] ds Datastore.
 * @param[in] with_deps What dependencies of the module are also needed.
 * @param[in,out] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_modules(sr_conn_ctx_t *conn, const struct lys_module *ly_mod, sr_datastore_t ds,
        int with_deps, struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules into mod info based on an operation data.
 *
 * @param[in] conn Connection to use.
 * @param[in] op_path Path identifying the operation.
 * @param[in] op Operation data tree.
 * @param[in] output Whether this is the operation output or input.
 * @param[out] shm_deps Main SHM operation dependencies.
 * @param[out] shm_dep_count Operation dependency count.
 * @param[in,out] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_op(sr_conn_ctx_t *conn, const char *op_path, const struct lyd_node *op, int output,
        sr_mod_data_dep_t **shm_deps, uint16_t *shm_dep_count, struct sr_mod_info_s *mod_info);

/**
 * @brief READ lock all modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] upgradable Whether the lock will be upgraded to WRITE later.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradable, sr_sid_t sid);

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
 * @brief Add/remove main SHM module configuration subscriptions.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] ds Datastore.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] add Whether to add or remove the subscription.
 * @param[out] last_removed Whether this is the last module configuration subscription that was removed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_conf_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_datastore_t ds, uint32_t priority, int sub_opts, uint32_t evpipe_num, int add, int *last_removed);

/**
 * @brief Add/remove main SHM module operational subscription.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] sub_type Data-provide subscription type.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] add Whether to add or remove the subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_oper_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_mod_oper_sub_type_t sub_type, uint32_t evpipe_num,int add);

/**
 * @brief Add/remove main SHM module RPC/action subscription.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] add Whether to add or remove the subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_rpc_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        uint32_t evpipe_num, int add);

/**
 * @brief Add/remove main SHM module notification subscriptions.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] add Whether to add or remove the subscription.
 * @param[out] last_removed Whether this is the last module notification subscription that was removed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_notif_subscription(sr_conn_ctx_t *conn, const char *mod_name, uint32_t evpipe_num, int add,
        int *last_removed);

/**
 * @brief Add an inverse dependency to a module, check for duplicities.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Name of the module to add inverse dependency into.
 * @param[in] inv_dep_mod_name Name offset of the module to be added as inverse dep into \p mod_name.
 * @param[in,out] shm_end Current main SHM end (will not be equal to size if main SHM was premapped), is updated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_add_inv_dep(sr_conn_ctx_t *conn, const char *mod_name, off_t inv_dep_mod_name, off_t *shm_end);

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
 * @brief Notify about (generate) a configuration update event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[out] update_edit Updated edit from subscribers, if any.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_notify_update(struct sr_mod_info_s *mod_info, sr_sid_t sid, struct lyd_node **update_edit,
        sr_error_info_t **cb_err_info);

/**
 * @brief Clear a configuration event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] ev Event to clear.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_notify_clear(struct sr_mod_info_s *mod_info, sr_sub_event_t ev);

/**
 * @brief Notify about (generate) a configuration change event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_notify_change(struct sr_mod_info_s *mod_info, sr_sid_t sid, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) a configuration done event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_notify_change_done(struct sr_mod_info_s *mod_info, sr_sid_t sid);

/**
 * @brief Notify about (generate) a configuration abort event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Originator sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_notify_change_abort(struct sr_mod_info_s *mod_info, sr_sid_t sid);

/**
 * @brief Notify about (generate) an operational event.
 *
 * @param[in] ly_mod Module to use.
 * @param[in] xpath Subscription XPath.
 * @param[in] parent Existing parent to append the data to.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[out] data Data provided by the subscriber.
 * @param[out] cb_err_info Callback error information generated by the subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_notify(const struct lys_module *ly_mod, const char *xpath, const struct lyd_node *parent,
        sr_sid_t sid, uint32_t evpipe_num, struct lyd_node **data, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action event.
 *
 * @param[in] xpath XPath of the operation.
 * @param[in] input Operation input tree.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[out] output Operation output returned by the subscriber.
 * @param[out] cb_err_info Callback error information generated by the subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify(const char *xpath, const struct lyd_node *input, sr_sid_t sid, uint32_t evpipe_num,
        struct lyd_node **output, sr_error_info_t **cb_err_info);

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
 * @brief Process all module configuration events, if any.
 *
 * @param[in] conf_subs Module configuration subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_conf_listen_process_module_events(struct modsub_conf_s *conf_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all module operational events, if any.
 *
 * @param[in] oper_subs Module operational subscriptions.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_listen_process_module_events(struct modsub_oper_s *oper_subs, sr_conn_ctx_t *conn);

/**
 * @brief Process all RPC/action events, if any.
 *
 * @param[in] rpc_sub RPC/action subscription.
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_listen_process_events(struct modsub_rpc_s *rpc_sub, sr_conn_ctx_t *conn);

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
 * May remap main SHM!
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
