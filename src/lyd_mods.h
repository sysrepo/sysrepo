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
 * @brief Check whether sysrepo module data file exists.
 *
 * @param[out] exists Whether the file exists.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_exists(int *exists);

/**
 * @brief Store (print) sysrepo module data.
 *
 * @param[in,out] sr_mods Data to store, are validated so could (in theory) be modified.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_print(struct lyd_node **sr_mods);

/**
 * @brief Create default sysrepo module data. All libyang internal implemented modules
 * are installed into sysrepo. Sysrepo internal modules ietf-netconf, ietf-netconf-with-defaults,
 * and ietf-netconf-notifications are also installed.
 *
 * @param[in] ly_ctx Context to use for creating the data.
 * @param[out] sr_mods_p Created default sysrepo module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_create(struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p);

/**
 * @brief Parse internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[out] sr_mods_p Sysrepo module data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_parse(struct ly_ctx *ly_ctx, struct lyd_node **sr_mods_p);

/**
 * @brief Load modules from sysrepo module data into context.
 *
 * @param[in] sr_mods Sysrepo module data.
 * @param[in] ly_ctx Context to load into.
 * @param[in] removed Whether to load removed modules.
 * @param[in] updated Whether to load updated modules.
 * @param[out] change Whether there were any removed or updated modules, if @p removed or @p updated was set.
 * @return error_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_ctx_load_modules(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx, int removed,
        int updated, int *change);

/**
 * @brief Apply all scheduled changes in sysrepo module data.
 *
 * @param[in,out] sr_mods Sysrepo modules data tree.
 * @param[in,out] new_ctx Initalized context with no SR modules loaded. On return all SR modules are loaded
 * with all the changes (if any) applied.
 * @param[out] change Whether sysrepo module data were changed.
 * @param[out] fail Whether some changes in @p new_ctx are not valid. In that case this context
 * is not usable and needs to be created anew.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_sched_apply(struct lyd_node *sr_mods, struct ly_ctx *new_ctx, int *change, int *fail);

/**
 * @brief Schedule module installation to sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module that is scheduled to be installed.
 * @param[in] features Array of enabled features.
 * @param[in] feat_count Number of enabled features.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_add_module(struct ly_ctx *ly_ctx, const struct lys_module *ly_mod, const char **features,
        int feat_count);

/**
 * @brief Unschedule module installation from sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] module_name Module name to unschedule.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_add_module(struct ly_ctx *ly_ctx, const char *module_name);

/**
 * @brief Load an installed module from sysrepo module data into a context with any other installed modules.
 *
 * @param[in] sr_mods Sysrepo modules data tree.
 * @param[in] ly_ctx Context to parse the module into.
 * @param[in] module_name Name of the module to find.
 * @param[out] ly_mod Parsed module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_ctx_load_installed_module_all(const struct lyd_node *sr_mods, struct ly_ctx *ly_ctx,
        const char *module_name, const struct lys_module **ly_mod);

/**
 * @brief Add startup data for a scheduled module to be installed. Replaces any previous data.
 *
 * @param[in] sr_mods Sysrepo modules sata tree.
 * @param[in] module_name Name of the scheduled installed module.
 * @param[in] data Data to set. They must have only nodes from the module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_add_module_data(struct lyd_node *sr_mods, const char *module_name,
        const struct lyd_node *data);

/**
 * @brief Schedule module deletion to sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module name to delete.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_del_module(struct ly_ctx *ly_ctx, const char *mod_name);

/**
 * @brief Unschedule module deletion from sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module that is scheduled to be deleted.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_del_module_with_imps(struct ly_ctx *ly_ctx, const struct lys_module *ly_mod);

/**
 * @brief Schedule module update to sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_upd_mod Update module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_upd_module(struct ly_ctx *ly_ctx, const struct lys_module *ly_upd_mod);

/**
 * @brief Unschedule module update from sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module name to be updated.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_unsched_upd_module(struct ly_ctx *ly_ctx, const char *mod_name);

/**
 * @brief Schedule a feature change (enable/disable) into sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] ly_mod Module with the feature.
 * @param[in] feat_name Feature name.
 * @param[in] to_enable Whether the feature should be enabled or disabled.
 * @param[in] is_enabled Whether the feature is currently enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_deferred_change_feature(struct ly_ctx *ly_ctx, const struct lys_module *ly_mod,
        const char *feat_name, int to_enable, int is_enabled);

/**
 * @brief Update reply support in sysrepo module data.
 *
 * @param[in] ly_ctx Context to use for parsing the data.
 * @param[in] mod_name Module to update. NULL to update all the modules.
 * @param[in] replay_support Whether replay should be enabled or disabled.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_update_replay_support(struct ly_ctx *ly_ctx, const char *mod_name, int replay_support);

#endif
