/**
 * @file lyd_mods.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sysrepo module data routines
 *
 * @copyright
 * Copyright 2019 CESNET, z.s.p.o.
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

#ifndef _LYD_MODS_H
#define _LYD_MODS_H

#include <libyang/libyang.h>

#include "common.h"

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
 * @brief Load stored lydmods data, apply any scheduled changes if possible, and update connection context.
 *
 * @param[in] main_shm Main SHM.
 * @param[in,out] ly_ctx libyang context to use, may be destroyed and created anew.
 * @param[in] apply_sched Whether we can attempt to apply scheduled changes.
 * @param[in] err_on_sched_fail Whether to return an error if applying scheduled changes fails.
 * @param[out] sr_mods Parsed lydmods data.
 * @param[out] changed Whether stored lydmods data were changed (created or scheduled changes applied).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_conn_ctx_update(sr_main_shm_t *main_shm, struct ly_ctx **ly_ctx, int apply_sched,
        int err_on_sched_fail, struct lyd_node **sr_mods, int *changed);

/**
 * @brief Schedule module installation to sysrepo module data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module that is scheduled to be installed.
 * @param[in] features Array of enabled features.
 * @param[in] feat_count Number of enabled features.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_add_module(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx,
        const struct lys_module *ly_mod, const char **features, int feat_count);

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
 * @param[in] main_shm Main SHM.
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module to update. NULL to update all the modules.
 * @param[in] replay_support Whether replay should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_update_replay_support(sr_main_shm_t *main_shm, struct ly_ctx *ly_ctx, const char *mod_name,
        int replay_support);

#endif
