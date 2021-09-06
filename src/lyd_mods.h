/**
 * @file lyd_mods.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sysrepo module data routines
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

#ifndef _LYD_MODS_H
#define _LYD_MODS_H

#include <pthread.h>

#include <libyang/libyang.h>

#include "shm_types.h"
#include "sysrepo_types.h"

/**
 * @brief Lock lydmods lock with a recovery callback.
 *
 * @param[in] lock Lydmods lock to lock.
 * @param[in] ly_ctx libyang context.
 * @param[in] func Name of the calling function for logging.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_lock(pthread_mutex_t *lock, const struct ly_ctx *ly_ctx, const char *func);

/**
 * @brief Parse internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[out] sr_mods_p Sysrepo module data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_parse(struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p);

/**
 * @brief Get current content-id of sysrepo modules.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx libyang context to use.
 * @param[out] cont_id Content ID.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_get_content_id(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, uint32_t *cont_id);

/**
 * @brief Load stored lydmods data, apply any scheduled changes if possible, and update connection context.
 *
 * @param[in] conn Connection to use.
 * @param[in,out] ly_ctx libyang context to use, may be destroyed and created anew.
 * @param[in] apply_sched Whether we can attempt to apply scheduled changes.
 * @param[in] err_on_sched_fail Whether to return an error if applying scheduled changes fails.
 * @param[out] changed Whether stored lydmods data were changed (created or scheduled changes applied).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_conn_ctx_update(sr_conn_ctx_t *conn, struct ly_ctx **ly_ctx, int apply_sched,
        int err_on_sched_fail, int *changed);

/**
 * @brief Load modules from sysrepo module data into context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] ly_ctx Context to load into.
 * @param[in] removed Whether to load removed modules.
 * @param[in] updated Whether to load updated modules.
 * @param[in] sched_features Whether to apply scheduled feature changes for any loaded modules.
 * @param[out] change Whether there were any removed or updated modules, if @p removed or @p updated was set.
 * @return error_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_ctx_load_modules(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx, int removed,
        int updated, int sched_features, int *change);

/**
 * @brief Schedule module installation to sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module that is scheduled to be installed.
 * @param[in] features Array of enabled features.
 * @param[in] module_ds Datastore implementation plugin name for each config datastore.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const struct lys_module *ly_mod, const char **features, const sr_module_ds_t *module_ds);

/**
 * @brief Unschedule module installation from sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] module_name Module name to unschedule.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *module_name);

/**
 * @brief Add startup data for a scheduled module to be installed. Replaces any previous data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] module_name Name of the scheduled installed module.
 * @param[in] data Data to set. Must be set if @p data_path is NULL.
 * @param[in] data_path Path of the data file to set. Must be set if @p data is NULL.
 * @param[in] format Format of @p data or @p data_path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_add_module_data(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const char *module_name, const char *data, const char *data_path, LYD_FORMAT format);

/**
 * @brief Schedule module deletion to sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module name to delete.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_del_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name);

/**
 * @brief Unschedule module deletion from sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module that is scheduled to be deleted.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_del_module_with_imps(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const struct lys_module *ly_mod);

/**
 * @brief Schedule module update to sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_upd_mod Update module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_upd_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const struct lys_module *ly_upd_mod);

/**
 * @brief Unschedule module update from sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module name to be updated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_upd_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name);

/**
 * @brief Schedule a feature change (enable/disable) into sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module with the feature.
 * @param[in] feat_name Feature name.
 * @param[in] to_enable Whether the feature should be enabled or disabled.
 * @param[in] is_enabled Whether the feature is currently enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_change_feature(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const struct lys_module *ly_mod, const char *feat_name, int to_enable, int is_enabled);

/**
 * @brief Update reply support in sysrepo module data.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_mod Module to update. NULL to update all the modules.
 * @param[in] replay_support Whether replay should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_update_replay_support(sr_conn_ctx_t *conn, const struct lys_module *ly_mod,
        int replay_support);

#endif
