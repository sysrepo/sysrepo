/**
 * @file plugins_datastore.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief API for datastore plugins
 *
 * @copyright
 * Copyright (c) 2021 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2022 CESNET, z.s.p.o.
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

////////////////////////////////////////////////////////////////////////////////
// Datastore Plugin API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup dsplg_api Datastore Plugin API
 * @{
 */

/**
 * @brief Datastore plugin API version
 */
#define SRPLG_DS_API_VERSION 8

/**
 * @brief Setup datastore of a newly installed module.
 *
 * Install is called once for every new installed module for each datastore. Right after that ::srds_init
 * is called. Afterwards, the data of the module must be valid meaning any following ::srds_load
 * __must return valid data__.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] owner Optional initial owner of the module data, process user by default.
 * @param[in] group Optional initial group of the module data, process group by default.
 * @param[in] perm Initial permissions of the module data, execute bits are never set.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_install)(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm);

/**
 * @brief Destroy data of an uninstalled module.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_uninstall)(const struct lys_module *mod, sr_datastore_t ds);

/**
 * @brief Initialize data of a newly installed module.
 *
 * Init is called after fresh reboot of the system for every module for each datastore.
 * Also, right after ::srds_install is called.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_init)(const struct lys_module *mod, sr_datastore_t ds);

/**
 * @brief Store data for a module. Either a diff can be applied manually or full new data tree stored.
 *
 * If @p ds is ::SR_DS_OPERATIONAL, it is actually an edit data tree that is being stored.
 * May be called simultaneously but with unique @p mod and @p ds pairs.
 *
 * Write access rights do not have to be checked, ::srds_access_check() is called before this callback.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] mod_diff Diff of currently stored module data and the new @p mod_data. __Not always available.__
 * @param[in] mod_data New module data tree to store.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_store)(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_diff,
        const struct lyd_node *mod_data);

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
 * This callback will be called with @p ds ::SR_DS_CANDIDATE only if the datastore is modified, otherwise
 * ::SR_DS_RUNNING is used directly. May be called simultanously but with unique @p mod and @p ds pairs.
 *
 * Read access rights do not have to be checked, ::srds_access_check() is called before this callback.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[in] xpaths Array of XPaths selecting the required data, NULL if all the module data are needed.
 * @param[in] xpath_count Number of @p xpaths.
 * @param[out] mod_data Loaded module data.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_load)(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths, uint32_t xpath_count,
        struct lyd_node **mod_data);

/**
 * @brief Copy data of a module from source datastore to the target datastore.
 *
 * Called only if this plugin is used for both datastores of a module.
 *
 * Read/write access rights do not have to be checked, ::srds_access_check() is called before this callback.
 *
 * @param[in] mod Specific module.
 * @param[in] trg_ds Target datastore.
 * @param[in] src_ds Source datastore.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_copy)(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds);

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
 * @param[in] perm Optional new permissions of the module data, execute bits are never set.
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
 * @brief Get the time when the datastore data of the module were last modified.
 *
 * The function succeedes even if the respective file does not exist. In such a case the @p mtime is set to 0.
 *
 * @param[in] mod Specific module.
 * @param[in] ds Specific datastore.
 * @param[out] mtime Time of last modification, or 0 when it is unknown.
 * @return ::SR_ERR_OK on success;
 * @return Sysrepo error value on error.
 */
typedef int (*srds_last_modif)(const struct lys_module *mod, sr_datastore_t ds, struct timespec *mtime);

/**
 * @brief Datastore plugin structure
 */
struct srplg_ds_s {
    const char *name;               /**< name of the datastore implementation plugin by which it is referenced */
    srds_install install_cb;        /**< callback for installing a new module */
    srds_uninstall uninstall_cb;    /**< callback for uninstalling a removed module */
    srds_init init_cb;              /**< callback for after-boot initialization of a module */
    srds_store store_cb;            /**< callback for storing module data */
    srds_recover recover_cb;        /**< callback for stored module data recovery */
    srds_load load_cb;              /**< callback for loading stored module data */
    srds_copy copy_cb;              /**< callback for copying stored module data from one datastore to another */
    srds_candidate_modified candidate_modified_cb;  /**< callback for checking whether candidate was modified */
    srds_candidate_reset candidate_reset_cb;        /**< callback for resetting candidate to running */
    srds_access_set access_set_cb;  /**< callback for setting access rights for module data */
    srds_access_get access_get_cb;  /**< callback for getting access rights for module data */
    srds_access_check access_check_cb;  /**< callback for checking user access to module data */
    srds_last_modif last_modif_cb;  /**< callback for getting the time of last modification */
};

/**
 * @brief Macro to define datastore plugin information in external plugins
 *
 * Use as follows:
 * SRPLG_DATASTORE = {<filled information of ::srplg_ds_s>};
 */
#define SRPLG_DATASTORE \
    uint32_t srpds_apiver__ = SRPLG_DS_API_VERSION; \
    const struct srplg_ds_s srpds__

/** @} dsplg_api */

#ifdef __cplusplus
}
#endif

#endif /* _SYSREPO_PLUGINS_DATASTORE_H */
