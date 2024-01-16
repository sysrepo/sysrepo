/**
 * @file lyd_mods.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sysrepo module data routines
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

#ifndef _LYD_MODS_H
#define _LYD_MODS_H

#include <libyang/libyang.h>

#include "common.h"
#include "shm_types.h"
#include "sysrepo_types.h"

/**
 * @brief Parse internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing SR data.
 * @param[in] conn Connection to use for DS handles.
 * @param[in,out] initialized If set, allow @p ly_ctx to be initialized with the internal modules, if not already.
 * @param[out] sr_mods_p Sysrepo module data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_parse(const struct ly_ctx *ly_ctx, sr_conn_ctx_t *conn, int *initialized,
        struct lyd_node **sr_mods_p);

/**
 * @brief Add modules to SR internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing SR data.
 * @param[in] conn Connection to use for DS handles.
 * @param[in,out] new_mods Array of new modules that were added, may be updated.
 * @param[in,out] new_mod_count Count of @p new_mods.
 * @param[out] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_change_add_modules(const struct ly_ctx *ly_ctx, sr_conn_ctx_t *conn,
        sr_int_install_mod_t **new_mods, uint32_t *new_mod_count, struct lyd_node **sr_mods);

/**
 * @brief Remove a module from SR internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing SR data.
 * @param[in] new_ctx Context with the module removed.
 * @param[in] mod_set Set of all the removed modules.
 * @param[in] conn Connection to use for DS handles.
 * @param[out] sr_del_mods Deleted modules from @p sr_mods.
 * @param[out] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_change_del_module(const struct ly_ctx *ly_ctx, const struct ly_ctx *new_ctx,
        const struct ly_set *mod_set, sr_conn_ctx_t *conn, struct lyd_node **sr_del_mods, struct lyd_node **sr_mods);

/**
 * @brief Update modules in SR internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing SR data.
 * @param[in] upd_mod_set Set with all the new updated modules.
 * @param[in] conn Connection to use for DS handles.
 * @param[out] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_change_upd_modules(const struct ly_ctx *ly_ctx, const struct ly_set *upd_mod_set,
        sr_conn_ctx_t *conn, struct lyd_node **sr_mods);

/**
 * @brief Change a feature (enable/disable) of a module in SR internal module data.
 *
 * @param[in] ly_ctx Context to use for parsing SR data.
 * @param[in] old_mod Module with the previous (current) state of features.
 * @param[in] new_mod Module with the features updated.
 * @param[in] feat_name Feature name.
 * @param[in] enable Whether the feature was enabled or disabled.
 * @param[in] conn Connection to use for DS handles.
 * @param[out] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_change_chng_feature(const struct ly_ctx *ly_ctx, const struct lys_module *old_mod,
        const struct lys_module *new_mod, const char *feat_name, int enable, sr_conn_ctx_t *conn, struct lyd_node **sr_mods);

/**
 * @brief Change replay support of a module in SR internal module data.
 *
 * @param[in] ly_mod Module to update. NULL to update all the modules.
 * @param[in] enable Whether replay should be enabled or disabled.
 * @param[in] mod_set Set of all the changed modules.
 * @param[in] conn Connection to use for NTF handles.
 * @param[out] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lydmods_change_chng_replay_support(const struct lys_module *ly_mod, int enable,
        struct ly_set *mod_set, sr_conn_ctx_t *conn, struct lyd_node **sr_mods);

#endif
