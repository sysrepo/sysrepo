/**
 * @file context_change.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for sysrepo context change routines
 *
 * @copyright
 * Copyright (c) 2021 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _CONTEXT_CHANGE_H
#define _CONTEXT_CHANGE_H

#include <libyang/libyang.h>

#include "common.h"
#include "common_types.h"
#include "sysrepo_types.h"

/**
 * @brief Structure for holding old and new data when being updated.
 */
struct sr_data_update_s {
    struct sr_data_update_set_s {
        struct lyd_node *start;
        struct lyd_node *run;
        int run_disabled;
        struct lyd_node *oper;
        struct lyd_node *fdflt;
    } old;
    struct sr_data_update_set_s new;
};

/**
 * @brief Lock context and update it if needed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Requested lock mode.
 * @param[in] lydmods_lock Set if SR internal module data will be modified.
 * @param[in] func Caller function name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock, const char *func);

/**
 * @brief Relock context.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Requested lock mode.
 * @param[in] func Caller function name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_relock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, const char *func);

/**
 * @brief Unlock context after it is no longer accessed.
 *
 * @param[in] conn Connection to use.
 * @param[in] mode Lock mode.
 * @param[in] lydmods_lock Set if SR internal module data were modified.
 * @param[in] func Caller function name.
 */
void sr_lycc_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int lydmods_lock, const char *func);

/**
 * @brief Check that modules can be added.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context with all the modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_add_modules(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx);

/**
 * @brief Finish adding new modules.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_mods Array of new modules.
 * @param[in] new_mod_count Count of @p new_mods.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_add_modules(sr_conn_ctx_t *conn, const sr_int_install_mod_t *new_mods, uint32_t new_mod_count);

/**
 * @brief Check that modules can be removed.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context without the modules.
 * @param[in] mod_set Set with all the removed modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_del_module(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct ly_set *mod_set);

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
 * @param[in] conn Connection to use.
 * @param[in] old_mod_set Set with all the old (previous) modules.
 * @param[in] upd_mod_set set with all the new updated module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_upd_modules(sr_conn_ctx_t *conn, const struct ly_set *old_mod_set,
        const struct ly_set *upd_mod_set);

/**
 * @brief Finish updating modules.
 *
 * @param[in] old_mod_set Set with all the old (previous) modules.
 * @param[in] upd_mod_set set with all the new updated module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_upd_modules(const struct ly_set *old_mod_set, const struct ly_set *upd_mod_set);

/**
 * @brief Check that a feature can be changed.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context with the feature changed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_check_chng_feature(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx);

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
 * @param[in] new_ctx New context.
 * @param[in] mod_data Optional new module initial data.
 * @param[in,out] data_info Old (current) data in @p conn context and new data in @p new_ctx.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_update_data(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx, const struct lyd_node *mod_data,
        struct sr_data_update_s *data_info);

/**
 * @brief Store updated SR data (destructively) for each module only if they differ from the current data.
 *
 * @param[in] conn Connection to use.
 * @param[in] new_ctx New context to iterate over.
 * @param[in,out] data_info Old (current) data and new data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lycc_store_data_if_differ(sr_conn_ctx_t *conn, const struct ly_ctx *new_ctx,
        const struct lyd_node *sr_mods, struct sr_data_update_s *data_info);

/**
 * @brief Free all the members of an update data info structure.
 *
 * @param[in] data_info Data info to clear.
 */
void sr_lycc_update_data_clear(struct sr_data_update_s *data_info);

#endif
