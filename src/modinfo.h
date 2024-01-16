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

#define MOD_INFO_NEW        0x0001 /* module was added (or an xpath) to mod info and needs to be consolidated */
#define MOD_INFO_DEP        0x0002 /* dependency module, its data cannot be changed, but are required for validation */
#define MOD_INFO_INV_DEP    0x0004 /* inverse dependency module, its data cannot be changed, but will be validated */
#define MOD_INFO_REQ        0x0008 /* required module, its data can be changed and it will be validated */
#define MOD_INFO_TYPE_MASK  0x000F /* mask for all module types */

#define MOD_INFO_RLOCK      0x0010 /* read-locked module (main DS) */
#define MOD_INFO_RLOCK_UPGR 0x0020 /* read-upgr-locked module (main DS) */
#define MOD_INFO_WLOCK      0x0040 /* write-locked module (main DS) */
#define MOD_INFO_RLOCK2     0x0080 /* read-locked module (secondary DS, it can be only read locked) */

#define MOD_INFO_DATA       0x0100 /* module data were loaded */
#define MOD_INFO_CHANGED    0x0200 /* module data were changed */
#define MOD_INFO_XPATH_DYN  0x0400 /* module XPaths are dynamically allocated and need to be freed */

/**
 * @brief Mod info structure, used for keeping all relevant modules for a data operation.
 */
struct sr_mod_info_s {
    sr_datastore_t ds;          /**< Main datastore we are working with. */
    sr_datastore_t ds2;         /**< Secondary datastore valid only if differs from the main one. Used only for locking. */
    struct lyd_node *diff;      /**< Diff with previous data. */
    struct lyd_node *data;      /**< Data tree. */
    int data_cached;            /**< Whether the data are actually cached. */
    sr_conn_ctx_t *conn;        /**< Associated connection. */

    struct sr_mod_info_mod_s {
        sr_mod_t *shm_mod;      /**< Module SHM structure. */
        const struct lys_module *ly_mod;    /**< Module libyang structure. */
        const struct sr_ds_handle_s *ds_handle[SR_DS_READ_COUNT];  /**< Module DS plugin handles, only the required ones are set. */
        const char **xpaths;    /**< XPaths selecting the required data from the module, all data if NULL. */
        uint32_t xpath_count;   /**< Count of XPaths. */
        uint32_t state;         /**< Module state (flags). */
        uint32_t request_id;    /**< Request ID of the published event. */
    } *mods;                    /**< Relevant modules. */
    uint32_t mod_count;         /**< Modules count. */
};

/**
 * @brief Add a new module and/or XPath into mod info.
 *
 * If the module is already in @p mod_info only an XPath is added to it, if any.
 *
 * @param[in] ly_mod Module to be added.
 * @param[in] xpath Optional XPath selecting the required data of @p ly_mod.
 * @param[in] dup_xpath Whether to duplicate @p xpath or use it directly.
 * @param[in] no_dup_check Skip duplicate module check and assume it was not yet added.
 * @param[in,out] mod_info Mod info to add the module to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_add(const struct lys_module *ly_mod, const char *xpath, int dup_xpath, int no_dup_check,
        struct sr_mod_info_s *mod_info);

/**
 * @brief Add all modules defining some data into mod info.
 *
 * @param[in] ly_ctx libyang context with all the modules.
 * @param[in] state_data Whether to add modules with state data only or not.
 * @param[in,out] mod_info Mod info to add to.
 */
sr_error_info_t *sr_modinfo_add_all_modules_with_data(const struct ly_ctx *ly_ctx, int state_data,
        struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules found in an edit in mod info.
 *
 * @param[in] edit Edit to be applied.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_collect_edit(const struct lyd_node *edit, struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules for evaluating XPath and getting selected data in mod info.
 *
 * @param[in] ly_ctx libyang context.
 * @param[in] xpath XPath to be evaluated.
 * @param[in] ds Target datastore where the @p xpath will be evaluated.
 * @param[in] store_xpath Whether to store @p xpath as module xpath (filtering required data).
 * @param[in] dup_xpath Whether to duplicate @p xpath if it is being stored.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_collect_xpath(const struct ly_ctx *ly_ctx, const char *xpath, sr_datastore_t ds,
        int store_xpath, int dup_xpath, struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules of (MOD_INFO_REQ & MOD_INFO_CHANGED) | MOD_INFO_INV_DEP modules in mod info.
 * Other modules will not be validated.
 *
 * @param[in,out] mod_info Mod info with the modules and data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_collect_deps(struct sr_mod_info_s *mod_info);

/**
 * @brief Collect required modules and XPath for all mounted data and parent-reference nodes in schema-mount ext data
 * in mod info.
 *
 * @param[in] mp_node Mount-point schema node.
 * @param[in,out] mod_info Mod info to add to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_collect_ext_deps(const struct lysc_node *mp_node, struct sr_mod_info_s *mod_info);

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
 * @brief Merge sysrepo edit with mod info data that are actually an edit as well.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] edit Sysrepo edit to merge.
 * @param[in] create_diff Whether to also create diff with the original data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_edit_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff);

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

#define SR_MI_NEW_DEPS          0x01    /**< new modules are not required (MOD_INFO_REQ) but only dpendencies (MOD_INFO_DEP) */
#define SR_MI_INV_DEPS          0x02    /**< add inverse dependencies for added modules */
#define SR_MI_LOCK_UPGRADEABLE  0x04    /**< only valid for a read lock, make it upgradeable into a write lock */
#define SR_MI_DATA_CACHE        0x08    /**< enable cache when loading module data */
#define SR_MI_DATA_NO           0x10    /**< do not load module data */
#define SR_MI_PERM_STRICT       0x20    /**< failed permission check causes an error instead of silent omission
                                             of the offending data */
#define SR_MI_PERM_NO           0x40    /**< do not check any permissions */
#define SR_MI_PERM_READ         0x80    /**< check read permissions of the MOD_INFO_REQ modules */
#define SR_MI_PERM_WRITE        0x0100  /**< check write permissions of the MOD_INFO_REQ modules */

/**
 * @brief Consolidate mod info by adding dependencies of the added modules, check the permissions, lock, and load data.
 *
 * @param[in,out] mod_info Mod info to consolidate.
 * @param[in] mod_lock Mode of module lock.
 * @param[in] mi_opts Mod info options modifying the default behavior but some SR_MI_PERM_* must always be used.
 * @param[in] sid Session ID to store in lock information.
 * @param[in] orig_name Event originator name.
 * @param[in] orig_data Event originator data.
 * @param[in] timeout_ms Timeout for operational callbacks.
 * @param[in] ds_lock_timeout_ms Timeout in ms for DS-lock in case it is required and locked, if 0 no waiting is performed.
 * @param[in] get_oper_opts Get oper data options, ignored if getting only ::SR_DS_OPERATIONAL data (edit).
 */
sr_error_info_t *sr_modinfo_consolidate(struct sr_mod_info_s *mod_info, sr_lock_mode_t mod_lock, int mi_opts,
        uint32_t sid, const char *orig_name, const void *orig_data, uint32_t timeout_ms, uint32_t ds_lock_timeout_ms,
        sr_get_oper_flag_t get_oper_opts);

/**
 * @brief Validate data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod_state Bitmask of state flags, module with at least one matching bit will be validated.
 * @param[in] finish_diff Whether to update diff with possible changes caused by validation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_validate(struct sr_mod_info_s *mod_info, uint32_t mod_state, int finish_diff);

/**
 * @brief Add default values into data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] finish_diff Whether to update diff with possible changes of default values.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_add_defaults(struct sr_mod_info_s *mod_info, int finish_diff);

/**
 * @brief Check data in mod info for state data nodes.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_check_state_data(struct sr_mod_info_s *mod_info);

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
 * @brief Publish "update" event for diff in mod info and update it is needed.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] session Sysrepo session.
 * @param[in] timeout_ms Timeout in milliseconds.
 * @param[in,out] change_sub_lock Current state of change subscription lock in ext SHM, is updated.
 * @param[out] cb_err_info Callback error information generated by a subscriber, if any.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_change_notify_update(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session,
        uint32_t timeout_ms, sr_lock_mode_t *change_sub_lock, sr_error_info_t **cb_err_info);

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
 * @brief Erase mod info.
 *
 * @param[in] mod_info Mod info to erase.
 */
void sr_modinfo_erase(struct sr_mod_info_s *mod_info);

#endif
