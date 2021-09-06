/**
 * @file modinfo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for modinfo routines
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

#ifndef _MODINFO_H
#define _MODINFO_H

#include <libyang/libyang.h>

#include "shm_types.h"
#include "sysrepo_types.h"

#define MOD_INFO_DEP        0x0001 /* dependency module, its data cannot be changed, but are required for validation */
#define MOD_INFO_INV_DEP    0x0002 /* inverse dependency module, its data cannot be changed, but will be validated */
#define MOD_INFO_REQ        0x0004 /* required module, its data can be changed and it will be validated */
#define MOD_INFO_TYPE_MASK  0x0007 /* mask for all module types */

#define MOD_INFO_RLOCK      0x0008 /* read-locked module (main DS) */
#define MOD_INFO_RLOCK_UPGR 0x0010 /* read-upgr-locked module (main DS) */
#define MOD_INFO_WLOCK      0x0020 /* write-locked module (main DS) */
#define MOD_INFO_RLOCK2     0x0040 /* read-locked module (secondary DS, it can be only read locked) */

#define MOD_INFO_DATA       0x0080 /* module data were loaded */
#define MOD_INFO_CHANGED    0x0100 /* module data were changed */

/**
 * @brief Mod info structure, used for keeping all relevant modules for a data operation.
 */
struct sr_mod_info_s {
    sr_datastore_t ds;          /**< Main datastore we are working with. */
    sr_datastore_t ds2;         /**< Secondary datastore valid only if differs from the main one. Used only for locking. */
    struct lyd_node *diff;      /**< Diff with previous data. */
    struct lyd_node *data;      /**< Data tree. */
    int data_cached;            /**< Whether the data are actually in cache (conn cache READ lock is held). */
    sr_conn_ctx_t *conn;        /**< Associated connection. */

    struct sr_mod_info_mod_s {
        sr_mod_t *shm_mod;      /**< Module SHM structure. */
        const struct lys_module *ly_mod;    /**< Module libyang structure. */
        struct srplg_ds_s *ds_plg;          /**< Module DS plugin. */
        uint32_t state;         /**< Module state (flags). */
        uint32_t request_id;    /**< Request ID of the published event. */
    } *mods;                    /**< Relevant modules. */
    uint32_t mod_count;         /**< Modules count. */
};

/**
 * @brief Check permissions of all the modules in a mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] wr Whether to check write or read permissions.
 * @param[in] strict Whether to return error if permission check fails or silently remove it from the modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr, int strict);

/**
 * @brief Get next mod_info mod in the order they are present in the data.
 *
 * @param[in] last Last returned mod_info mod, NULL on first call.
 * @param[in] mod_info mod_info structure to use.
 * @param[in] data Data to determine the order.
 * @param[in,out] aux Auxiliary array that tracks returned modules. Allocated on first call, freed when returning NULL.
 * @return Next mod_info mod, NULL if last was returned.
 */
struct sr_mod_info_mod_s *sr_modinfo_next_mod(struct sr_mod_info_mod_s *last, struct sr_mod_info_s *mod_info,
        const struct lyd_node *data, uint32_t **aux);

/**
 * @brief Apply sysrepo edit on mod info data, in the same order.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] edit Sysrepo edit to apply.
 * @param[in] create_diff Whether to also create diff with the original data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff);

/**
 * @brief Merge sysrepo diff to mod info diff.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] new_diff New diff to merge into existing diff in mod_info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_diff_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *new_diff);

/**
 * @brief Replace mod info data with new data.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in,out] src_data New data to set, are spent.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_replace(struct sr_mod_info_s *mod_info, struct lyd_node **src_data);

/**
 * @brief Read-lock all changed modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_changesub_rdlock(struct sr_mod_info_s *mod_info);

/**
 * @brief Read-unlock all changed modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 */
void sr_modinfo_changesub_rdunlock(struct sr_mod_info_s *mod_info);

/**
 * @brief Load data for modules in mod info.
 * Should not be called directly because it is normally a part of ::sr_modinfo_add_modules()!
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] cache Whether it makes sense to use cached data, if available.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] request_id XPath of the data request.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options, ignored if getting only ::SR_DS_OPERATIONAL data (edit).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_data_load(struct sr_mod_info_s *mod_info, int cache, const char *orig_name, const void *orig_data,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t opts);

#define SR_MI_MOD_DEPS          0x01    /**< add modules not as MOD_INFO_REQ but as MOD_INFO_DEP */
#define SR_MI_LOCK_UPGRADEABLE  0x02    /**< only valid for a read lock, make it upgradeable into a write lock */
#define SR_MI_DATA_CACHE        0x04    /**< enable cache when loading module data */
#define SR_MI_DATA_NO           0x08    /**< do not load module data */
#define SR_MI_PERM_STRICT       0x10    /**< failed permission check causes an error instead of silent omission
                                             of the offending data */
#define SR_MI_PERM_NO           0x20    /**< do not check any permissions */
#define SR_MI_PERM_READ         0x40    /**< check read permissions of the MOD_INFO_REQ modules */
#define SR_MI_PERM_WRITE        0x80    /**< check write permissions of the MOD_INFO_REQ modules */

/**
 * @brief Add new modules and their dependnecies into mod_info, check their permissions, lock, and load their data.
 *
 * @param[in,out] mod_info Mod info to use.
 * @param[in] mod_set Module set with modules to add to @p mod_info.
 * @param[in] mod_deps Dependency modules to add for each added module. 0 for adding no dependency modules.
 * @param[in] mod_lock Mode of module lock.
 * @param[in] mi_opts Mod info options modifying the default behavior but some SR_MI_PERM_* must always be used.
 * @param[in] sid Session ID to store in lock information.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] request_xpath Request XPath for operational callbacks.
 * @param[in] timeout_ms Timeout for operational callbacks.
 * @param[in] get_opts Get operational data options, ignored if getting only ::SR_DS_OPERATIONAL data (edit).
 */
sr_error_info_t *sr_modinfo_add_modules(struct sr_mod_info_s *mod_info, const struct ly_set *mod_set, int mod_deps,
        sr_lock_mode_t mod_lock, int mi_opts, uint32_t sid, const char *orig_name, const void *orig_data,
        const char *request_xpath, uint32_t timeout_ms, sr_get_oper_options_t get_opts);

/**
 * @brief Validate data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod_state Bitmask of state flags, module with at least one matching but will be validated.
 * @param[in] finish_diff Whether to update diff with possible changes caused by validation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_validate(struct sr_mod_info_s *mod_info, int mod_state, int finish_diff);

/**
 * @brief Add default values into data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] finish_diff Whether to update diff with possible changes of default values.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_add_defaults(struct sr_mod_info_s *mod_info, int finish_diff);

/**
 * @brief Validate operation using modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] op Operation data tree (RPC/action/notification).
 * @param[in] output Whether this is the output of an operation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, int output);

/**
 * @brief Filter data from mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] xpath Selected data.
 * @param[in] session Sysrepo session.
 * @param[out] result Resulting set of matching nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session,
        struct ly_set **result);

/**
 * @brief Generate a netconf-config-change notification based on changes in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] session Session to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session);

/**
 * @brief Store data (persistently) from mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_data_store(struct sr_mod_info_s *mod_info);

/**
 * @brief Reset (unlock SHM files) all candidate data for mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_candidate_reset(struct sr_mod_info_s *mod_info);

/**
 * @brief Check whether there are any modified modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return Whether there are any changed modules or not.
 */
int sr_modinfo_is_changed(struct sr_mod_info_s *mod_info);

/**
 * @brief Free mod info.
 *
 * @param[in] mod_info Mod info to free.
 */
void sr_modinfo_free(struct sr_mod_info_s *mod_info);

#endif
