/**
 * @file common_json.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines for JSON header
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

#ifndef _COMMON_JSON_H
#define _COMMON_JSON_H

#define _GNU_SOURCE

#include <sys/types.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

/** suffix of backed-up JSON files */
#define SRPJSON_FILE_BACKUP_SUFFIX ".bck"

/** permissions of new directories */
#define SRPJSON_DIR_PERM 00777

/** permissions of new notification files */
#define SRPJSON_NOTIF_PERM 00600

/** notification file will never exceed this size (kB) */
#define SRPJSON_NOTIF_FILE_MAX_SIZE 1024

/**
 * @brief Wrapper for writev().
 *
 * @param[in] plg_name Plugin name.
 * @param[in] fd File desriptor.
 * @param[in] iov Buffer vectors to write.
 * @param[in] iovcnt Number of vector buffers.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_writev(const char *plg_name, int fd, struct iovec *iov, int iovcnt);

/**
 * @brief Wrapper for read().
 *
 * @param[in] plg_name Plugin name.
 * @param[in] fd File desriptor.
 * @param[out] buf Read memory.
 * @param[in] count Number of bytes to read.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_read(const char *plg_name, int fd, void *buf, size_t count);

/**
 * @brief Check file existence.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path Path to the file to check.
 * @return Whether the file exists or not.
 */
int srpjson_file_exists(const char *plg_name, const char *path);

/**
 * @brief Get global SHM prefix prepended to all SHM files.
 *
 * @param[in] plg_name Plugin name.
 * @param[out] prefix SHM prefix to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_shm_prefix(const char *plg_name, const char **prefix);

/**
 * @brief Get datastore string name.
 *
 * @param[in] ds Datastore to transform.
 * @return Datastore string name.
 */
const char *srpjson_ds2str(sr_datastore_t ds);

/**
 * @brief Log libyang error (or warning) from the context.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] ly_ctx libyang context to get the error from.
 * @return err_info.
 */
sr_error_info_t *srpjson_log_err_ly(const char *plg_name, const struct ly_ctx *ly_ctx);

/**
 * @brief Wrapper for open(2).
 *
 * Additionally sets umask.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path Path of the file to open.
 * @param[in] flags Flags to use.
 * @param[in] mode Permissions for the file in case it is created.
 * @return Opened file descriptor.
 * @return -1 on error, errno set.
 */
int srpjson_open(const char *plg_name, const char *path, int flags, mode_t mode);

/**
 * @brief Generate plugin error on failed open.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path Path of the file to open.
 * @return err_info.
 */
sr_error_info_t *srpjson_open_error(const char *plg_name, const char *path);

/**
 * @brief Get the UID of a user or vice versa.
 *
 * @param[in] plg_name Plugin name.
 * @param[in,out] uid UID.
 * @param[in,out] user User name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_pwd(const char *plg_name, uid_t *uid, char **user);

/**
 * @brief Get GID from group name or vice versa.
 *
 * @param[in] plg_name Plugin name.
 * @param[in,out] gid GID.
 * @param[in,out] group Group name.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_grp(const char *plg_name, gid_t *gid, char **group);

/**
 * @brief Change mode (permissions) and/or owner and group of a file.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path File path.
 * @param[in] owner New owner if not NULL.
 * @param[in] group New group if not NULL.
 * @param[in] perm New permissions if not 0.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_chmodown(const char *plg_name, const char *path, const char *owner, const char *group, mode_t perm);

/**
 * @brief Copy file contents to another file.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] to Destination file path, must exist.
 * @param[in] from Source file path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_cp_path(const char *plg_name, const char *to, const char *from);

/**
 * @brief Create all directories in the path, wrapper for mkdir(2).
 *
 * Additionally sets umask.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path Full path, is temporarily modified.
 * @param[in] mode Mode (permissions) of the directories.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_mkpath(const char *plg_name, char *path, mode_t mode);

/**
 * @brief Compare 2 timespec structures.
 *
 * @param[in] ts1 First timespec.
 * @param[in] ts2 Second timespec.
 * @return 0, if the @p ts1 and @p ts2 are equal;
 * @return a negative value if @p ts1 is sooner (smaller) than @p ts2;
 * @return a positive value if @p ts1 is later (larger) than @p ts2.
 */
int srpjson_time_cmp(const struct timespec *ts1, const struct timespec *ts2);

/**
 * @brief Get the path to startup files directory.
 *
 * @param[in] plg_name Plugin name.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_startup_dir(const char *plg_name, char **path);

/**
 * @brief Get path to a datastore file of a module.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] mod_name Module name.
 * @param[in] ds Specific datastore.
 * @param[out] path Generated file path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_path(const char *plg_name, const char *mod_name, sr_datastore_t ds, char **path);

/**
 * @brief Get path to a datastore permission file of a module.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] mod_name Module name.
 * @param[in] ds Specific volatile datastore.
 * @param[out] path Generated file path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_perm_path(const char *plg_name, const char *mod_name, sr_datastore_t ds, char **path);

/**
 * @brief Get the path to notification files directory.
 *
 * @param[in] plg_name Plugin name.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_notif_dir(const char *plg_name, char **path);

/**
 * @brief Get the path to a module notification file.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] mod_name Module name.
 * @param[in] from_ts Timestamp of the first stored notification.
 * @param[in] to_ts Timestamp of the last stored notification.
 * @param[out] path Created path.
 * @return err_info, NULL on success.
 */
sr_error_info_t *srpjson_get_notif_path(const char *plg_name, const char *mod_name, time_t from_ts, time_t to_ts, char **path);

/**
 * @brief Check whether a module defines any instantiable data nodes (ignoring operations).
 *
 * @param[in] ly_mod Module to examine.
 * @param[in] state_data Whether to accept even state data or must be configuration.
 * @return Whether the module has data or not.
 */
int srpjson_module_has_data(const struct lys_module *ly_mod, int state_data);

#endif /* _COMMON_JSON_H */
