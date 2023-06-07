/**
 * @file shm_ext.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for ext SHM routines
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

#ifndef _SHM_EXT_H
#define _SHM_EXT_H

#include "shm_types.h"
#include "sysrepo_types.h"

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
 * @brief Open (and init if needed) Ext SHM.
 *
 * @param[in,out] shm SHM structure to use.
 * @param[in] zero Whether to zero (or init) Ext SHM.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_open(sr_shm_t *shm, int zero);

/**
 * @brief Debug print the contents of ext SHM.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] shm_ext Ext SHM.
 */
void sr_shmext_print(sr_mod_shm_t *mod_shm, sr_shm_t *shm_ext);

/**
 * @brief Add main SHM module change subscription and create sub SHM if the first subscription was added.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] ds Datastore.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id,
        const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num);

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
 * @param[in] ds Datastore.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_change_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id);

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
 * @brief Add main SHM module operational get subscription, create sub SHM, notify oper poll subs.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @param[in] path Subscription path.
 * @param[in] sub_type Data-provide subscription type.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[out] prio Retrieves subscription priority.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_get_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *path,
        sr_mod_oper_get_sub_type_t sub_type, int sub_opts, uint32_t evpipe_num, uint32_t *prio);

/**
 * @brief Remove main SHM module operational get subscription and unlink sub SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_get_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id);

/**
 * @brief Remove main SHM module operational get subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx1 Index of the list of subscriptions with the same XPath.
 * @param[in] del_idx2 Index of the XPath subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_get_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx1, uint32_t del_idx2,
        int del_evpipe, sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Add main SHM module operational poll subscription.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @param[in] path Subscription path.
 * @param[in] sub_opts Subscription options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_poll_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *path,
        int sub_opts, uint32_t evpipe_num);

/**
 * @brief Remove main SHM module operational poll subscription.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_poll_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id);

/**
 * @brief Remove main SHM module operational poll subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_poll_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx,
        int del_evpipe, sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Add main SHM module notification subscription and create sub SHM if the first subscription was added.
 * Ext SHM may be remapped!
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] evpipe_num Subscription event pipe number.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_notif_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *xpath,
        uint32_t evpipe_num);

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
 * @param[in] sub_lock SHM RPC subs lock.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC path.
 * @param[in] sub_id Unique sub ID.
 * @param[in] xpath Subscription XPath.
 * @param[in] priority Subscription priority.
 * @param[in] sub_opts Subscriptions options.
 * @param[in] evpipe_num Subscription event pipe number.
 * @param[in] sub_cid Subscription CID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_add(sr_conn_ctx_t *conn, sr_rwlock_t *sub_lock, off_t *subs, uint32_t *sub_count,
        const char *path, uint32_t sub_id, const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num,
        sr_cid_t sub_cid);

/**
 * @brief Remove main SHM RPC/action subscription and unlink sub SHM if the last subscription was removed.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC path.
 * @param[in] sub_id Unique sub ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_del(sr_conn_ctx_t *conn, off_t *subs, uint32_t *sub_count, const char *path,
        uint32_t sub_id);

/**
 * @brief Remove main SHM module RPC/action subscription with param-based cleanup.
 *
 * @param[in] conn Connection to use.
 * @param[in] sub_lock SHM RPC subs lock.
 * @param[in,out] subs Offset in ext SHM of RPC subs.
 * @param[in,out] sub_count Ext SHM RPC sub count.
 * @param[in] path RPC path.
 * @param[in] del_idx Index of the subscription to free.
 * @param[in] del_evpipe Whether to also remove the evpipe.
 * @param[in] has_locks Mode of held CHANGE SUB and EXT locks.
 * @param[in] recovery Whether to print subscription recovery warning.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_rpc_sub_stop(sr_conn_ctx_t *conn, sr_rwlock_t *sub_lock, off_t *subs, uint32_t *sub_count,
        const char *path, uint32_t del_idx, int del_evpipe, sr_lock_mode_t has_locks, int recovery);

/**
 * @brief Recover all subscriptions in ext SHM, their connection must be dead.
 *
 * @param[in] conn Connection to use.
 */
void sr_shmext_recover_sub_all(sr_conn_ctx_t *conn);

/**
 * @brief Check validity of all the subscriptions in a new updated context.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New updated context.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_check_sub_all(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx);

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
 * @brief Get or set operational get subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_get_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id,
        int set_suspended, int *get_suspended);

/**
 * @brief Get or set operational poll subscription suspended state (flag).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_name Module name.
 * @param[in] sub_id Subscription ID.
 * @param[in] set_suspended Set suspended to this value, leave unmodified if -1.
 * @param[out] get_suspended Current suspended state.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmext_oper_poll_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id,
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

#endif /* _SHM_EXT_H */
