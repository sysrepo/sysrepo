/**
 * @file plugins_datastore.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief API for datastore plugins
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

#ifndef _SYSREPO_PLUGINS_DATASTORE_H
#define _SYSREPO_PLUGINS_DATASTORE_H

#include <stdint.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "sysrepo_types.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Datastore plugin API version
 */
#define SRPLG_DS_API_VERSION 4

/**
 * @brief Initialize data of a new module.
 *
 * Initialization is called once for every new installed module for each datastore.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] owner Optional initial owner of the module data, process user by default.
 * @param[in] group Optional initial group of the module data, process group by default.
 * @param[in] perm Initial permissions of the module data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_init)(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm);

/**
 * @brief Destroy data of a removed module.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_destroy)(const struct lys_module *mod, sr_datastore_t ds);

/**
 * @brief Store data for a module.
 *
 * if @p ds is ::SR_DS_OPERATIONAL, it is actually an edit data tree that is being stored.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] mod_data Module data to store.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_store)(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_data);

/**
 * @brief Recover module data when a crash occurred while they were being written.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 */
typedef void (*srds_recover)(const struct lys_module *mod, sr_datastore_t ds);

/**
 * @brief Load data of a module.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] xpaths Array of XPaths selecting the required data, NULL if all the module data are needed.
 * @param[in] xpath_count Number of @p xpaths.
 * @param[out] mod_data Loaded module data.
 * @return ::SR_ERR_OK on success;
 * @return ::SR_ERR_NOT_FOUND if the candidate datastore was not modified and mirrors running, only for @p ds ::SR_DS_CANDIDATE;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_load)(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths, uint32_t xpath_count,
        struct lyd_node **mod_data);

/**
 * @brief Load cached running datastore data of specific modules. Optional callback.
 *
 * For the duration of this callback and while @p data are being used, a READ lock for the connection is being held.
 * Data must always be connection-specific because each connection uses its own libyang context.
 *
 * @param[in] cid Connection ID of the cache.
 * @param[in] mods Array of modules.
 * @param[in] mod_count Number of @p mods.
 * @param[out] data Cached data of at least all the @p mods.
 * @return ::SR_ERR_OK on success;
 * @return ::SR_ERR_OPERATION_FAILED if some of @p mods data need to be updated first;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_running_load_cached)(sr_cid_t cid, const struct lys_module **mods, uint32_t mod_count,
        const struct lyd_node **data);

/**
 * @brief Update cached running datastore data of specific modules. Optional callback.
 *
 * For the duration of this callback, a WRITE lock for the connection is held.
 *
 * @param[in] cid Connection ID of the cache.
 * @param[in] mods Array of modules.
 * @param[in] mod_count Number of @p mods.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_running_update_cached)(sr_cid_t cid, const struct lys_module **mods, uint32_t mod_count);

/**
 * @brief Flush cached data. Optional callback.
 *
 * No lock is held as none is needed.
 *
 * @param[in] cid Connection ID of the cache.
 */
typedef void (*srds_running_flush_cached)(sr_cid_t cid);

/**
 * @brief Copy data of a module from source datastore to the target datastore.
 *
 * Called only if this plugin is used for both datastores of a module.
 *
 * @param[in] mod Specific module.
 * @param[in] trg_ds Target datastore.
 * @param[in] src_ds Source datastore.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_copy)(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds);

/**
 * @brief Check whether module data differ after some context update. If so, they are stored.
 *
 * @param[in] old_mod Specific module of @p old_mod_data.
 * @param[in] old_mod_data Pre-update module data.
 * @param[in] new_mod Specific module of @p new_mod_data.
 * @param[in] new_mod_data Post-update module data.
 * @param[out] differ Whether @p old_mod_data and @p new_mod_data differ and need to be replaced.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_update_differ)(const struct lys_module *old_mod, const struct lyd_node *old_mod_data,
        const struct lys_module *new_mod, const struct lyd_node *new_mod_data, int *differ);

/**
 * @brief Learn whether the candidate datastore was modified and is different from running.
 *
 * @param[in] mod Specific module.
 * @param[out] modified Whether the candidate datastore data were modified or not.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_candidate_modified)(const struct lys_module *mod, int *modified);

/**
 * @brief Reset candidate datastore to "no changes" - mirroring running.
 *
 * @param[in] mod Specific module.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_candidate_reset)(const struct lys_module *mod);

/**
 * @brief Set access permissions for datastore data of a module.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] owner Optional new owner of the module data.
 * @param[in] group Optional new group of the module data.
 * @param[in] perm Optional new permissions of the module data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_access_set)(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm);

/**
 * @brief Get access permissions for datastore data of a module. This function is also used for sysrepo access
 * control checks for the module when ::SR_DS_STARTUP is used.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[out] owner Optional owner of the module data.
 * @param[out] group Optional group of the module data.
 * @param[out] perm Optional permissions of the module data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_access_get)(const struct lys_module *mod, sr_datastore_t ds, char **owner, char **group, mode_t *perm);

/**
 * @brief Check whether the current user has the required access to datastore data.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[out] read Optional, whether the read permission was granted or not.
 * @param[out] write Optional, whether the write permission was granted or not.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_access_check)(const struct lys_module *mod, sr_datastore_t ds, int *read, int *write);

/**
 * @brief Datastore plugin structure
 */
struct srplg_ds_s {
    const char *name;               /**< name of the datastore implementation plugin by which it is referenced */
    srds_init init_cb;              /**< callback for initialization of a new module */
    srds_destroy destroy_cb;        /**< callback for freeing a removed module */
    srds_store store_cb;            /**< callback for storing module data */
    srds_recover recover_cb;        /**< callback for stored module data recovery */
    srds_load load_cb;              /**< callback for loading stored module data */
    srds_running_load_cached running_load_cached_cb;    /**< callback for loading cached running module data */
    srds_running_update_cached running_update_cached_cb;    /**< callback for updating cached running module data */
    srds_running_flush_cached running_flush_cached_cb;  /**< callback for flushin cached running module data */
    srds_copy copy_cb;              /**< callback for copying stored module data from one datastore to another */
    srds_update_differ update_differ_cb;            /**< callback for checking for data difference after an update */
    srds_candidate_modified candidate_modified_cb;  /**< callback for checking whether candidate was modified */
    srds_candidate_reset candidate_reset_cb;        /**< callback for resetting candidate to running */
    srds_access_set access_set_cb;  /**< callback for setting access rights for module data */
    srds_access_get access_get_cb;  /**< callback for getting access rights for module data */
    srds_access_check access_check_cb;  /**< callback for checking user access to module data */
};

/**
 * @brief Macro to define datastore plugin information in external plugins
 *
 * Use as follows:
 * SRPLG_DATASTORE = {<filled information of ::srplg_ds_s>};
 */
#define SRPLG_DATASTORE \
    uint32_t srpds_apiver__ = SRPLG_DS_API_VERSION; \
    extern const struct srplg_ds_s srpds__

#ifdef __cplusplus
}
#endif

#endif /* _SYSREPO_PLUGINS_DATASTORE_H */
