/**
 * @file shm_mod.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for mod SHM routines
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

#ifndef _SHM_MOD_H
#define _SHM_MOD_H

#include "shm_types.h"
#include "sysrepo_types.h"

struct ly_ctx;
struct ly_set;
struct lyd_node;
struct lys_module;
struct sr_mod_info_s;
struct srplg_ds_s;

/** macro for getting a SHM module on a specific index */
#define SR_SHM_MOD_IDX(mod_shm_addr, idx) ((sr_mod_t *)(((char *)mod_shm_addr) + SR_SHM_SIZE(sizeof(sr_mod_shm_t)) + \
        idx * sizeof(sr_mod_t)))

/**
 * @brief Open (and init if needed) Mod SHM.
 *
 * @param[in,out] shm SHM structure to use.
 * @param[in] zero Whether to zero (or init) Mod SHM.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_open(sr_shm_t *shm, int zero);

/**
 * @brief Find a specific SHM module.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] name Name of the module.
 * @return Found SHM module, NULL if not found.
 */
sr_mod_t *sr_shmmod_find_module(sr_mod_shm_t *mod_shm, const char *name);

/**
 * @brief Find a specific SHM module RPC.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] path Path of the RPC/ation.
 * @return Found SHM RPC, NULL if not found.
 */
sr_rpc_t *sr_shmmod_find_rpc(sr_mod_shm_t *mod_shm, const char *path);

/**
 * @brief Remap mod SHM and store modules and all their static information (name, deps, ...) in it
 * overwriting any previous modules.
 *
 * @param[in] shm_mod Mod SHM structure.
 * @param[in] sr_mods SR internal module data to read from.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_store_modules(sr_shm_t *shm_mod, const struct lyd_node *sr_mods);

/**
 * @brief Load modules stored in mod SHM into a context.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in,out] ly_ctx libyang context to update.
 * @param[in] skip_mod_set Optional set of modules to skip.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_ctx_load_modules(sr_mod_shm_t *mod_shm, struct ly_ctx *ly_ctx, const struct ly_set *skip_mod_set);

/**
 * @brief Get SHM dependencies of an RPC/action.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] path Path identifying the RPC/action.
 * @param[in] output Whether this is the RPC/action output or input.
 * @param[out] shm_deps Mod SHM dependencies.
 * @param[out] shm_dep_count Dependency count.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_get_rpc_deps(sr_mod_shm_t *mod_shm, const char *path, int output, sr_dep_t **shm_deps,
        uint16_t *shm_dep_count);

/**
 * @brief Get SHM dependencies of a notification.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] notif_mod Module of the notification.
 * @param[in] path Path identifying the notification.
 * @param[out] shm_deps Mod SHM dependencies.
 * @param[out] shm_dep_count Dependency count.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_get_notif_deps(sr_mod_shm_t *mod_shm, const struct lys_module *notif_mod, const char *path,
        sr_dep_t **shm_deps, uint16_t *shm_dep_count);

/**
 * @brief Collect required module dependencies from a SHM dependency array.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] shm_deps Array of SHM dependencies.
 * @param[in] shm_dep_count Number of @p shm_deps.
 * @param[in] ly_ctx libyang context.
 * @param[in] data Data to look for instance-identifiers in.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_collect_deps(sr_mod_shm_t *mod_shm, sr_dep_t *shm_deps, uint16_t shm_dep_count,
        struct ly_ctx *ly_ctx, const struct lyd_node *data, struct sr_mod_info_s *mod_info);

/**
 * @brief Information structure for the SHM module recovery callback.
 */
struct sr_shmmod_recover_cb_s {
    struct ly_ctx **ly_ctx_p;   /**< Pointer to context to get sysrepo module from, may be changed. */
    sr_datastore_t ds;          /**< Datastore being recovered. */
    const struct srplg_ds_s *ds_plg;    /**< Datastore plugin of the module being recovered. */
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
 * @param[in] ds_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock(struct sr_mod_info_s *mod_info, int upgradeable, uint32_t sid,
        uint32_t ds_timeout_ms);

/**
 * @brief WRITE lock all modules in mod info. Secondary DS modules, if any, are READ locked.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @param[in] ds_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_wrlock(struct sr_mod_info_s *mod_info, uint32_t sid, uint32_t ds_timeout_ms);

/**
 * @brief Upgrade READ lock on modules in mod info to WRITE lock.
 * Works only for upgradeable READ lock, in which case there will only be one
 * thread waiting for WRITE lock.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] sid Sysrepo session ID.
 * @param[in] ds_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_modinfo_rdlock_upgrade(struct sr_mod_info_s *mod_info, uint32_t sid, uint32_t ds_timeout_ms);

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

/**
 * @brief Change replay support of a module in mod SHM.
 *
 * @param[in] mod_shm Mod SHM.
 * @param[in] mod_set Set of all the modules to change.
 * @param[in] enable Whether replay support should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_update_replay_support(sr_mod_shm_t *mod_shm, const struct ly_set *mod_set, int enable);

/**
 * @brief Copy startup DS to running DS after reboot after SHM was created.
 *
 * @param[in] conn Connection to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_shmmod_copy_startup_to_running(sr_conn_ctx_t *conn);

#endif /* _SHM_MOD_H */
