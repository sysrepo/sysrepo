/**
 * @file shm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

#define SR_MAIN_SHM "/sr_main"              /**< Main SHM name. */
#define SR_MAIN_SHM_LOCK "sr_main_lock"     /**< Main SHM file lock name. */

/**
 * @brief Main SHM module dependency type.
 */
typedef enum sr_mod_dep_type_e {
    SR_DEP_REF,         /**< Module reference (leafref, when, must). */
    SR_DEP_INSTID,      /**< Instance-identifier. */
} sr_mod_dep_type_t;

/**
 * @brief Main SHM module data dependency.
 * (typedef sr_mod_data_dep_t)
 */
struct sr_mod_data_dep_s {
    sr_mod_dep_type_t type;     /**< Dependency type. */
    off_t module;               /**< Dependant module name. */
    off_t xpath;                /**< XPath of the node with the dependency. */
};

/**
 * @brief Main SHM module operation dependency.
 */
typedef struct sr_mod_op_dep_s {
    off_t xpath;                /**< XPath of the node with the dependency. */
    off_t in_deps;              /**< Input operation dependencies (also notification). */
    uint16_t in_dep_count;      /**< Input dependency count. */
    off_t out_deps;             /**< Output operation dependencies. */
    uint16_t out_dep_count;     /**< Output dependency count. */
} sr_mod_op_dep_t;

/**
 * @brief Main SHM module configuration subscriptions.
 */
typedef struct sr_mod_conf_sub_s {
    off_t xpath;
    uint32_t priority;
    int opts;
} sr_mod_conf_sub_t;

/**
 * @brief Main SHM module data-provide subscription type.
 */
typedef enum sr_mod_dp_sub_type_e {
    SR_DP_SUB_NONE = 0,         /**< Invalid type. */
    SR_DP_SUB_STATE,            /**< Data-provide of state data. */
    SR_DP_SUB_CONFIG,           /**< Data-provide of configuration data. */
    SR_DP_SUB_MIXED,            /**< Data provide of both state and configuration data. */
} sr_mod_dp_sub_type_t;

/**
 * @brief Main SHM module data-provide subscription.
 */
typedef struct sr_mod_dp_sub_s {
    off_t xpath;                /**< XPath of the subscription. */
    sr_mod_dp_sub_type_t sub_type;  /**< Type of the subscription. */
} sr_mod_dp_sub_t;

/**
 * @brief Main SHM RPC/action subscription.
 */
typedef struct sr_mod_rpc_sub_s {
    off_t xpath;                /**< XPath of the RPC/action subscribed to. */
} sr_mod_rpc_sub_t;

#define SR_MOD_REPLAY_SUPPORT 0x01  /**< Flag for module with replay support. */

/**
 * @brief Main SHM module.
 * (typedef sr_mod_t)
 */
struct sr_mod_s {
    off_t name;                 /**< Module name. */
    char rev[11];               /**< Module revision. */
    uint8_t flags;              /**< Module flags. */

    uint32_t ver;               /**< Module data version (non-zero). */
    struct sr_mod_lock_s {
        sr_rwlock_t lock;       /**< Process-shared lock for accessing module data. */
        uint8_t write_locked;   /**< Whether module data are WRITE locked (lock may not be WRITE locked to allow data reading). */
        uint8_t ds_locked;      /**< Whether module data are datastore locked (NETCONF locks). */
        sr_sid_t sid;           /**< Session ID of the locking session. */
    } data_lock_info[2];        /**< Module data lock information for each datastore. */
    sr_rwlock_t replay_lock;    /**< Process-shared lock for accessing stored notifications for replay. */
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
    } conf_sub[2];              /**< Configuration subscriptions for each datastore. */

    off_t dp_subs;              /**< Array of data-provide subscriptions. */
    uint16_t dp_sub_count;      /**< Number of data-provide subscriptions. */

    off_t rpc_subs;             /**< Array of RPC/action subscriptions. */
    uint16_t rpc_sub_count;     /**< Number of RPC/action subscriptions. */

    uint16_t notif_sub_count;   /**< Number of notification subscriptions. */

    off_t next;                 /**< Next module structure. */
};

/**
 * @brief Main SHM.
 */
typedef struct sr_main_shm_s {
    sr_rwlock_t lock;           /**< Process-shared lock for accessing main SHM. */
    uint32_t ver;               /**< Main SHM version (installed module set version). */
    ATOMIC_T new_sr_sid;        /**< SID for new session. */
    size_t wasted_mem;          /**< Number of bytes wasted in main SHM. */
    off_t first_mod;            /**< First module structure. */
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
    SR_SUB_EV_DP,               /**< New data-provide event ready. */
    SR_SUB_EV_RPC,              /**< New RPC/action event ready. */
    SR_SUB_EV_NOTIF,            /**< New notification event ready. */
} sr_sub_event_t;

/** Whether an event is one to be processed by the listeners (subscribers). */
#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_DP) || (ev == SR_SUB_EV_RPC) || (ev == SR_SUB_EV_NOTIF))

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
 * event SR_EV_UPDATE, SR_EV_CHANGE, SR_EV_DONE, SR_EV_ABORT - char *diff_lyb - diff tree
 *
 * FOR ORIGINATOR (when subscriber_count is 0)
 * followed by:
 * event SR_EV_UPDATE - char *edit_lyb
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * notification subscription SHM (multi)
 *
 * FOR SUBSCRIBERS
 * followed by:
 * event SR_EV_CHANGE - time_t notif_timestamp; char *notif_lyb - notification
 */

/*
 * data provider subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_EV_CHANGE - char *parent_lyb - existing data tree parent
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_EV_NONE - char *data_lyb - parent with state data connected
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * RPC subscription SHM (generic)
 *
 * FOR SUBSCRIBER
 * followed by:
 * event SR_EV_CHANGE - char *input_lyb - RPC/action with input
 *
 * FOR ORIGINATOR
 * followed by:
 * event SR_EV_NONE - char *data_lyb - RPC/action with output
 * or if err_code is set - char *error_message; char *error_xpath
 */

/*
 * Main SHM low-level functions, use with caution with respect to locks, ...
 */

/**
 * @brief Debug print the contents of main SHM.
 *
 * @param[in] main_shm_addr Main SHM starting address.
 * @param[in] main_shm_size Main SHM size.
 */
void
sr_shmmain_print(char *main_shm_addr, size_t main_shm_size);

/**
 * @brief Defragment main SHM.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] main_shm_size Main SHM size.
 * @param[in] wasted_mem Currently wasted memory.
 * @param[out] defrag_mem Defragmented main SHM memory copy.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_defrag(char *main_shm_addr, size_t main_shm_size, size_t wasted_mem, char **defrag_mem);

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
 * @brief Main SHM module iterator.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] last Last returned module, NULL on first call.
 * @return Next main SHM module.
 */
sr_mod_t *sr_shmmain_getnext(char *main_shm_addr, sr_mod_t *last);

/**
 * @brief Find a specific main SHM module.
 *
 * Either of name or name_off must be set.
 *
 * @param[in] main_shm_addr Main SHM mapping address.
 * @param[in] name String name of the module.
 * @param[in] name_off Main SHM offset of the name of the module (faster lookup, no need for strcmp()).
 * @return Main SHM module, NULL if not found.
 */
sr_mod_t *sr_shmmain_find_module(char *main_shm_addr, const char *name, off_t name_off);

/**
 * @brief Lock main SHM and remap it if needed (it was changed).
 *
 * @param[in] conn Connection to use.
 * @param[in] wr Whether to WRITE or READ lock main SHM.
 * @param[in] keep_remap Whether to keep remap lock for cases when main SHM can be modified (resized) and
 * will be, again, remapped.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_lock_remap(sr_conn_ctx_t *conn, int wr, int keep_remap);

/**
 * @brief Unlock main SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] wr Whether to WRITE or READ unlock main SHM.
 * @param[in] kept_remap Whether remap lock was kept so it needs unlocking as well.
 */
void sr_shmmain_unlock(sr_conn_ctx_t *conn, int wr, int kept_remap);

/**
 * @brief Add a module with any imports into main SHM and persistent internal data.
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
 * @param[in] mod_name Module name to update.
 * @param[in] rev Revision of the update module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_deferred_upd_module(sr_conn_ctx_t *conn, const char *mod_name, const char *rev);

/**
 * @brief Unschedule module update from persistent internal data.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name to be updated.
 * @param[out] revision Revision the module was supposed to be updated to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_unsched_upd_module(sr_conn_ctx_t *conn, const char *mod_name, char **revision);

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
 * @param[in] xpath XPath identifying the operation.
 * @param[in] op Operation data tree.
 * @param[in] output Whether this is the operation output or input.
 * @param[out] shm_deps Main SHM operation dependencies.
 * @param[out] shm_dep_count Operation dependency count.
 * @param[in,out] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_op(sr_conn_ctx_t *conn, const char *xpath, const struct lyd_node *op, int output,
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
 * @brief Add/remove main SHM module configuration subscriptions.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] ds Datastore.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] add Whether to add or remove the subscription.
 * @param[out] last_removed Whether this is the last module configuration subscription that was removed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_conf_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_datastore_t ds, uint32_t priority, int sub_opts, int add, int *last_removed);

/**
 * @brief Add/remove main SHM module data-provide subscription.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] sub_type Data-provide subscription type.
 * @param[in] add Whether to add or remove the subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_dp_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath,
        sr_mod_dp_sub_type_t sub_type, int add);

/**
 * @brief Add/remove main SHM module RPC/action subscription.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] xpath Subscription XPath.
 * @param[in] add Whether to add or remove the subscription.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_rpc_subscription(sr_conn_ctx_t *conn, const char *mod_name, const char *xpath, int add);

/**
 * @brief Add/remove main SHM module notification subscriptions.
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] add Whether to add or remove the subscription.
 * @param[out] last_removed Whether this is the last module notification subscription that was removed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_notif_subscription(sr_conn_ctx_t *conn, const char *mod_name, int add, int *last_removed);

/**
 * @brief Add an inverse dependency to a module, check for duplicities.
 * May remap main SHM!
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Name of the module to add inverse dependency into.
 * @param[in] inv_dep_mod_name Name offset of the module to be added as inverse dep into \p mod_name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_add_inv_dep(sr_conn_ctx_t *conn, const char *mod_name, off_t inv_dep_mod_name);

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
 * @brief Notify about (generate) a data-provide event.
 *
 * @param[in] ly_mod Module to use.
 * @param[in] xpath Subscription XPath.
 * @param[in] parent Existing parent to append the data to.
 * @param[in] sid Originator sysrepo session ID.
 * @param[out] data Data provided by the subscriber.
 * @param[out] cb_err_info Callback error information generated by the subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_dp_notify(const struct lys_module *ly_mod, const char *xpath, const struct lyd_node *parent,
        sr_sid_t sid, struct lyd_node **data, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action event.
 *
 * @param[in] xpath XPath of the operation.
 * @param[in] input Operation input tree.
 * @param[in] sid Originator sysrepo session ID.
 * @param[out] output Operation output returned by the subscriber.
 * @param[out] cb_err_info Callback error information generated by the subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify(const char *xpath, const struct lyd_node *input, sr_sid_t sid,
        struct lyd_node **output, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) a notification event.
 *
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @param[in] sid Originator sysrepo session ID.
 * @param[in] notif_sub_count Number of subscribers.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_notify(const struct lyd_node *notif, time_t notif_ts, sr_sid_t sid,
        uint32_t notif_sub_count);

/**
 * @brief Listener handler thread of all subscriptions.
 *
 * @param[in] arg Pointer to the subscription structure.
 * @return Always NULL.
 */
void *sr_shmsub_listen_thread(void *arg);

#endif
