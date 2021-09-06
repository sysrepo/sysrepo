/**
 * @file shm.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for all SHM routines
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

#ifndef _SHM_H
#define _SHM_H

#include "shm_types.h"
#include "sysrepo_types.h"

struct sr_mod_info_s;

#define SR_MAIN_SHM_LOCK "sr_main_lock"     /**< Main SHM file lock name. */
#define SR_SHM_VER 8                        /**< Main and ext SHM version of their expected content structures. */

/**
 * Main SHM organization
 *
 * Except for main and ext SHM there are individual SHM segments for subscriptions and
 * running data files.
 */

/** Whether an event is one to be processed by the listeners (subscribers). */
#define SR_IS_LISTEN_EVENT(ev) ((ev == SR_SUB_EV_UPDATE) || (ev == SR_SUB_EV_CHANGE) || (ev == SR_SUB_EV_DONE) \
        || (ev == SR_SUB_EV_ABORT) || (ev == SR_SUB_EV_OPER) || (ev == SR_SUB_EV_RPC) \
        || (ev == SR_SUB_EV_NOTIF))

/** Whether an event is one to be processed by the originators. */
#define SR_IS_NOTIFY_EVENT(ev) ((ev == SR_SUB_EV_SUCCESS) || (ev == SR_SUB_EV_ERROR))

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
 * @brief Check if the connection is alive.
 *
 * @param[in] cid The connection ID to check.
 * @param[out] conn_alive Will be set to non-zero if the connection is alive, zero otherwise.
 * @param[out] pid Optional PID set if the connection is alive.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_check(sr_cid_t cid, int *conn_alive, pid_t *pid);

/**
 * @brief Add a connection into the process connection list.
 *
 * @param[in] cid Connection ID of the connection to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_list_add(sr_cid_t cid);

/**
 * @brief Remove a connection from the process connection list.
 *
 * @param[in] cid Connection ID of the connection to remove.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_conn_list_del(sr_cid_t cid);

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
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_files_startup2running(sr_conn_ctx_t *conn);

/**
 * @brief Remap main SHM and store modules and all their static information (name, deps, ...) in it.
 *
 * @param[in] conn Connection to use.
 * @param[in] first_sr_mod First module to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_store_modules(sr_conn_ctx_t *conn, struct lyd_node *first_sr_mod);

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
 * @param[in] main_shm Main SHM.
 * @param[in] name Name of the module.
 * @return Found SHM module, NULL if not found.
 */
sr_mod_t *sr_shmmain_find_module(sr_main_shm_t *main_shm, const char *name);

/**
 * @brief Find a specific main SHM module RPC.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] path Path of the RPC/ation.
 * @return Found SHM RPC, NULL if not found.
 */
sr_rpc_t *sr_shmmain_find_rpc(sr_main_shm_t *main_shm, const char *path);

/**
 * @brief Change replay support of a module in main SHM.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] mod_name Module name. NUll for all the modules.
 * @param[in] replay_support Whether replay support should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmain_update_replay_support(sr_main_shm_t *main_shm, const char *mod_name, int replay_support);

/*
 * Ext SHM functions
 */

/**
 * @brief Lock ext SHM lock and connection remap lock, remap ext SHM if needed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Mode of the remap lock.
 * @param[in] ext_lock Whether to lock ext lock.
 * @param[in] func Caller function name for logging.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_conn_remap_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func);

/**
 * @brief Unlock ext SHM lock and connection remap lock, truncate ext SHM if possible.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Mode of the ext and remap lock.
 * @param[in] ext_lock Whether to unlock ext lock.
 * @param[in] func Caller function name for logging.
 */
void sr_shmext_conn_remap_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func);

/**
 * @brief Debug print the contents of ext SHM.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] shm_ext Ext SHM.
 */
void sr_shmext_print(sr_main_shm_t *main_shm, sr_shm_t *shm_ext);

/**
 * @brief Add main SHM module change subscription and create sub SHM if the first subscription was added.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] has_lock Whether CHANGE SUB lock is already held.
 * @param[in] ds Datastore.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock,
        sr_datastore_t ds, uint32_t sub_id, const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Modify existing main SHM module change subscription.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] ds Datastore.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath New subscription XPath.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_modify(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id,
        const char *xpath);

/**
 * @brief Remove main SHM module change subscription and unlink sub SHM if the last subscription was removed.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] has_lock Whether CHANGE SUB lock is already held.
 * @param[in] ds Datastore.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock,
        sr_datastore_t ds, uint32_t sub_id);

/**
 * @brief Remove main SHM module change subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] ds Subscription datastore.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx,
        int del_evpipe, sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Add main SHM module operational subscription and create sub SHM.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] sub_type Data-provide subscription type.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *xpath,
        sr_mod_oper_sub_type_t sub_type, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM module operational subscription and unlink sub SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id);

/**
 * @brief Remove main SHM module operational subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Add main SHM module notification subscription and create sub SHM if the first subscription was added.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[out] listen_since Timestamp of the moment the subscription is listening for notifications.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_notif_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num,
        struct timespec *listen_since);

/**
 * @brief Remove main SHM module notification subscription and unlink sub SHM if the last subscription was removed.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_notif_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id);

/**
 * @brief Remove main SHM module notification subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_notif_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Add main SHM RPC/action subscription and create sub SHM if the first subscription was added.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscriptions options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_add(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t sub_id, const char *xpath,
        uint32_t priority, int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM RPC/action subscription and unlink sub SHM if the last subscription was removed.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_del(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t sub_id);

/**
 * @brief Remove main SHM module RPC/action subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_stop(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Recover all subscriptions in ext SHM, their connection must be dead.
 *
 * @param[in] conn Connection to use.
 */
void sr_shmext_recover_sub_all(sr_conn_ctx_t *conn);

/**
 * @brief Get or set change subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] ds Subscription datastore.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, sr_datastore_t ds,
        uint32_t sub_id, int set_suspended, int *get_suspended);

/**
 * @brief Get or set operational subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id,
        int set_suspended, int *get_suspended);

/**
 * @brief Get or set notification subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_notif_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id,
        int set_suspended, int *get_suspended);

/**
 * @brief Get or set RPC/action subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] path RPC/action path.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_suspended(sr_conn_ctx_t *conn, const char *path, uint32_t sub_id, int set_suspended,
        int *get_suspended);

/*
 * Main SHM module functions
 */

/**
 * @brief Collect required modules found in an edit.
 *
 * @param[in] edit Edit to be applied.
 * @param[in,out] mod_set Set of modules to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_edit(const struct lyd_node *edit, struct ly_set *mod_set);

/**
 * @brief Collect required modules for evaluating XPath and getting selected data.
 *
 * @param[in] ly_ctx libyang context.
 * @param[in] xpath XPath to be evaluated.
 * @param[in] ds Target datastore where the @p xpath will be evaluated.
 * @param[in,out] mod_set Set of modules to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds,
        struct ly_set *mod_set);

/**
 * @brief Collect required modules for an RPC/action validation.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx libyang context.
 * @param[in] path Path identifying the RPC/action.
 * @param[in] output Whether this is the RPC/action output or input.
 * @param[in,out] mod_set Set of modules to add to.
 * @param[out] shm_deps Main SHM dependencies.
 * @param[out] shm_dep_count Dependency count.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_rpc_deps(sr_main_shm_t *main_shm, const struct ly_ctx *ly_ctx, const char *path,
        int output, struct ly_set *mod_set, sr_dep_t **shm_deps, uint16_t *shm_dep_count);

/**
 * @brief Collect required modules for a notification validation.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] notif_mod Module of the notification.
 * @param[in] path Path identifying the notification.
 * @param[in,out] mod_set Set of modules to add to.
 * @param[out] shm_deps Main SHM dependencies.
 * @param[out] shm_dep_count Dependency count.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_notif_deps(sr_main_shm_t *main_shm, const struct lys_module *notif_mod, const char *path,
        struct ly_set *mod_set, sr_dep_t **shm_deps, uint16_t *shm_dep_count);

/**
 * @brief Collect required modules of instance-identifiers found in data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] shm_deps SHM dependencies of relevant instance-identifiers.
 * @param[in] shm_dep_count SHM dependency count.
 * @param[in] ly_ctx libyang context.
 * @param[in] data Data to look for instance-identifiers in.
 * @param[in,out] mod_set Set of modules to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_instid_deps_data(sr_main_shm_t *main_shm, sr_dep_t *shm_deps, uint16_t shm_dep_count,
        struct ly_ctx *ly_ctx, const struct lyd_node *data, struct ly_set *mod_set);

/**
 * @brief Collect required modules of instance-identifiers found in
 * (MOD_INFO_REQ & MOD_INFO_CHANGED) | MOD_INFO_INV_DEP modules in mod info. Other modules will not be validated.
 *
 * @param[in] mod_info Mod info with the modules and data.
 * @param[in,out] mod_set Set of modules to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_instid_deps_modinfo(const struct sr_mod_info_s *mod_info, struct ly_set *mod_set);

/**
 * @brief Information structure for the SHM module recovery callback.
 */
struct sr_shmmod_recover_cb_s {
    const struct lys_module *ly_mod;
    sr_datastore_t ds;
    struct srplg_ds_s *ds_plg;
};

/**
 * @brief Recovery callback for SHM module data locks.
 * Recover possibly backed-up data file.
 */
void sr_shmmod_recover_cb(sr_lock_mode_t mode, sr_cid_t cid, void *data);

/**
 * @brief READ lock all modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] upgradeable Whether the lock will be upgraded to WRITE later. Used only for main DS of @p mod_info!
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradeable, uint32_t sid);

/**
 * @brief WRITE lock all modules in mod info. Secondary DS modules, if any, are READ locked.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, uint32_t sid);

/**
 * @brief Upgrade READ lock on modules in mod info to WRITE lock.
 * Works only for upgradeable READ lock, in which case there will only be one
 * thread waiting for WRITE lock.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, uint32_t sid);

/**
 * @brief Downgrade WRITE lock on modules in mod info to READ lock.
 * Works only for upgraded READ lock.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_wrlock_downgrade(struct sr_mod_info_s *mod_info, uint32_t sid);

/**
 * @brief Unlock mod info.
 *
 * @param[in] mod_info Mod info to use.
 */
void sr_shmmod_modinfo_unlock(struct sr_mod_info_s *mod_info);

/**
 * @brief Release any locks matching the provided SID.
 *
 * @param[in] conn Connection to use.
 * @param[in] sid Sysrepo session ID.
 */
void sr_shmmod_release_locks(sr_conn_ctx_t *conn, uint32_t sid);

/*
 * Subscription SHM functions.
 */

/**
 * @brief Create and initialize a subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[in] shm_struct_size Size of the used subscription SHM structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_create(const char *name, const char *suffix1, int64_t suffix2, size_t shm_struct_size);

/**
 * @brief Open and map an existing subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @param[out] shm Mapped SHM.
 * @param[in] shm_struct_size Size of the used subscription SHM structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_open_map(const char *name, const char *suffix1, int64_t suffix2, sr_shm_t *shm);

/**
 * @brief Unlink a subscription SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_unlink(const char *name, const char *suffix1, int64_t suffix2);

/**
 * @brief Unlink a subscription data SHM.
 *
 * @param[in] name Subscription name (module name).
 * @param[in] suffix1 First suffix.
 * @param[in] suffix2 Second suffix, none if set to -1.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_data_unlink(const char *name, const char *suffix1, int64_t suffix2);

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
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] update_edit Updated edit from subscribers, if any.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_update(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, struct lyd_node **update_edit, sr_error_info_t **cb_err_info);

/**
 * @brief Clear a change event.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_clear(struct sr_mod_info_s *mod_info);

/**
 * @brief Notify about (generate) a change "change" event.
 * Main SHM read lock must be held and may be temporarily unlocked!
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) a change "done" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_done(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) a change "abort" event.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Change callback timeout in milliseconds. Set to 0 if the event should not be waited for.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_change_notify_change_abort(struct sr_mod_info_s *mod_info, const char *orig_name,
        const void *orig_data, uint32_t timeout_ms);

/**
 * @brief Notify about (generate) an operational event.
 *
 * @param[in] ly_mod Module to use.
 * @param[in] xpath Subscription XPath.
 * @param[in] request_xpath Requested XPath.
 * @param[in] parent Existing parent to append the data to.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] evpipe_num Subscriber event pipe number.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] cid Connection ID.
 * @param[out] data Data provided by the subscriber.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_oper_notify(const struct lys_module *ly_mod, const char *xpath, const char *request_xpath,
        const struct lyd_node *parent, const char *orig_name, const void *orig_data, uint32_t evpipe_num,
        uint32_t timeout_ms, sr_cid_t cid, struct lyd_node **data, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action event.
 * Main SHM read lock must be held and may be temporarily unlocked!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] op_path Path identifying the RPC/action.
 * @param[in] input Operation input tree.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[in,out] request_id Generated request ID, set to 0 when passing.
 * @param[out] output Operation output returned by the last subscriber on success.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *op_path,
        const struct lyd_node *input, const char *orig_name, const void *orig_data, uint32_t timeout_ms,
        uint32_t *request_id, struct lyd_node **output, sr_error_info_t **cb_err_info);

/**
 * @brief Notify about (generate) an RPC/action abort event.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC.
 * @param[in] op_path Path identifying the RPC/action.
 * @param[in] input Operation input tree.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds.
 * @param[in] request_id Generated request ID from previous event.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_rpc_notify_abort(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *op_path,
        const struct lyd_node *input, const char *orig_name, const void *orig_data, uint32_t timeout_ms, uint32_t request_id);

/**
 * @brief Notify about (generate) a notification event.
 *
 * @param[in] conn Connection to use.
 * @param[in] notif Notification data tree.
 * @param[in] notif_ts Notification timestamp.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Notification callback timeout in milliseconds. Used only if @p wait is set.
 * @param[in] wait Whether to wait for the callbacks or not.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_notify(sr_conn_ctx_t *conn, const struct lyd_node *notif, struct timespec notif_ts,
        const char *orig_name, const void *orig_data, uint32_t timeout_ms, int wait);

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
 * @brief Get nearest stop time of a subscription, if any.
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in,out] stop_time_in Nearest stop time of a subscription, if none, left unmodified.
 */
void sr_shmsub_notif_listen_module_get_stop_time_in(struct modsub_notif_s *notif_subs, struct timespec *stop_time_in);

/**
 * @brief Check notification subscriptions stop time and finish the subscription if it has elapsed.
 * Main SHM read-upgr lock must be held and will be temporarily upgraded!
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] has_subs_lock What kind of SUBS lock is held.
 * @param[in] subscr Subscriptions structure.
 * @param[out] module_finished Whether the last module notification subscription was finished.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_stop_time(struct modsub_notif_s *notif_subs, sr_lock_mode_t has_subs_lock,
        sr_subscription_ctx_t *subscr, int *module_finished);

/**
 * @brief Check notification subscription replay state and perform it if requested.
 * Main SHM read-upgr lock must be held and will be temporarily upgraded!
 * May remap ext SHM!
 *
 * @param[in] notif_subs Module notification subscriptions.
 * @param[in] subscr Subscriptions structure.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmsub_notif_listen_module_replay(struct modsub_notif_s *notif_subs, sr_subscription_ctx_t *subscr);

/**
 * @brief Listener handler thread of all subscriptions.
 *
 * @param[in] arg Pointer to the subscription structure.
 * @return Always NULL.
 */
void *sr_shmsub_listen_thread(void *arg);

#endif /* _SHM_H */
