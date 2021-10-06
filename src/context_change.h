/**
 * @file context_change.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sysrepo context change routines
 *
 * @copyright
 * Copyright (c) 2021 Deutsche Telekom AG.
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _CONTEXT_CHANGE_H
#define _CONTEXT_CHANGE_H

#include "common_types.h"
#include "sysrepo_types.h"

/**
 * @brief Lock context and update it if needed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Requested lock mode.
 * @param[in] lydmods_lock Set if SR internal module data will be modified.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock);

/**
 * @brief Relock context.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Requested lock mode.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_relock(sr_conn_ctx_t *conn, sr_lock_mode_t mode);

/**
 * @brief Unlock context after it is no longer accessed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Lock mode.
 * @param[in] lydmods_lock Set if SR internal module data were modified.
 */
void sr_lycc_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock);

/**
 * @brief Check that a module can be added.
 *
 * @param[in] new_ctx New context with the module.
 * @param[in] old_ctx Previous (current) context.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_add_module(const struct ly_ctx *new_ctx, const struct ly_ctx *old_ctx);

/**
 * @brief Finish adding a new module(s).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_set Set with all the new modules.
 * @param[in] module_ds Module datastore plugins for the module(s).
 * @param[in] owner Optional initial owner of the module data.
 * @param[in] group Optional initial group of the module data.
 * @param[in] perm Optional initial permissions of the module data.
 * @param[in] init_start_only Whether to initialize only ::SR_DS_STARTUP or all the datastores.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_add_module(sr_conn_ctx_t *conn, const struct ly_set *mod_set, const sr_module_ds_t *module_ds,
        const char *owner, const char *group, mode_t perm, int init_start_only);

/**
 * @brief Check that modules can be removed.
 *
 * @param[in] ly_ctx New context without the modules.
 * @param[in] mod_set Set with all the removed modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_del_module(const struct ly_ctx *ly_ctx, const struct ly_set *mod_set);

/**
 * @brief Finish removing modules.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_ctx New context without the removed modules.
 * @param[in] mod_set Set with all the removed modules.
 * @param[in] sr_del_mods SR internal module data of the deleted modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_del_module(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, const struct ly_set *mod_set,
        const struct lyd_node *sr_del_mods);

/**
 * @brief Check that a module can be updated.
 *
 * @param[in] upd_mod New updated module.
 * @param[in] old_mod Previous module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_upd_module(const struct lys_module *upd_mod, const struct lys_module *old_mod);

/**
 * @brief Finish updating a module.
 *
 * @param[in] upd_mod Updated module.
 * @param[in] old_mod Previous module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_upd_module(const struct lys_module *upd_mod, const struct lys_module *old_mod);

/**
 * @brief Finish changing the replay-support of a module(s).
 *
 * @param[in] conn Connection to use.
 * @param[in] mod_set Set of all the changed modules.
 * @param[in] enable Whether the replay-support is enabled or disabled.
 * @param[in] sr_mods SR internal module data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_set_replay_support(sr_conn_ctx_t *conn, const struct ly_set *mod_set, int enable,
        const struct lyd_node *sr_mods);

/**
 * @brief Update SR data for use with the changed context.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_ctx New context.
 * @param[in] mod_data Optional new module initial data.
 * @param[out] old_s_data Previous (current) startup data in @p conn context.
 * @param[out] new_s_data New startup data in @p ly_ctx.
 * @param[out] old_r_data Previous (current) running data in @p conn context.
 * @param[out] new_r_data New running data in @p ly_ctx.
 * @param[out] old_o_data Previous (current) operational data in @p conn context.
 * @param[out] new_o_data New operational data in @p ly_ctx.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_update_data(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx, const struct lyd_node *mod_data,
        struct lyd_node **old_s_data, struct lyd_node **new_s_data, struct lyd_node **old_r_data,
        struct lyd_node **new_r_data, struct lyd_node **old_o_data, struct lyd_node **new_o_data);

/**
 * @brief Store updated SR data (destructively) for each module only if they differ from the current data.
 *
 * @param[in] conn Connection to use.
 * @param[in] ly_ctx New context to iterate over.
 * @param[in,out] old_s_data Previous (current) startup data.
 * @param[in,out] new_s_data New startup data.
 * @param[in,out] old_r_data Previous (current) running data.
 * @param[in,out] new_r_data New running data.
 * @param[in,out] old_o_data Previous (current) operational data.
 * @param[in,out] new_o_data New operational data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_store_data_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *ly_ctx,
        const struct lyd_node *sr_mods, struct lyd_node **old_s_data, struct lyd_node **new_s_data,
        struct lyd_node **old_r_data, struct lyd_node **new_r_data, struct lyd_node **old_o_data,
        struct lyd_node **new_o_data);

#endif
