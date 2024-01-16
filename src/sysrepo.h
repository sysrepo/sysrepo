/**
 * @file sysrepo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief public API sysrepo header
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _SYSREPO_H
#define _SYSREPO_H

#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "sysrepo_types.h"

#ifdef __cplusplus
extern "C" {
#endif

////////////////////////////////////////////////////////////////////////////////
// Logging API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup log_api Logging API
 * @{
 */

/**
 * @brief Returns the error message corresponding to the error code.
 *
 * @param[in] err_code Error code.
 * @return Error message (statically allocated, do not free).
 */
const char *sr_strerror(int err_code);

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to
 * standard error output.
 *
 * By default, logging to stderr is disabled. Setting log level to any value
 * other than ::SR_LL_NONE enables the logging to stderr. Setting log level
 * back to ::SR_LL_NONE disables the logging to stderr.
 *
 * @note Please note that this will overwrite your libyang logging settings.
 * Also, only libyang errors are printed, if enabled.
 *
 * @param[in] log_level Requested log level (verbosity).
 */
void sr_log_stderr(sr_log_level_t log_level);

/**
 * @brief Learn current standard error output log level.
 *
 * @return stderr log level.
 */
sr_log_level_t sr_log_get_stderr(void);

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to system log.
 *
 * By default, logging into syslog is disabled. Setting log level to any value
 * other than ::SR_LL_NONE enables the logging into syslog. Setting log level
 * back to ::SR_LL_NONE disables the logging into syslog.
 *
 * Library messages are logged with LOG_USER facility and plugin (syrepo-plugind) messages are
 * logged with LOG_DAEMON facility.
 *
 * @note Please note that enabling logging into syslog will overwrite your syslog
 * connection settings (calls openlog), if you are connected to syslog already and
 * also libyang logging settings.
 *
 * @param[in] app_name Name of the application. If not set, "sysrepo" will be used.
 * @param[in] log_level Requested log level (verbosity).
 */
void sr_log_syslog(const char *app_name, sr_log_level_t log_level);

/**
 * @brief Learn current system log log level.
 *
 * @return syslog log level.
 */
sr_log_level_t sr_log_get_syslog(void);

/**
 * @brief Sets callback that will be called when a log entry would be populated.
 * Callback will be called for every message __regardless__ of any log level.
 *
 * @param[in] log_callback Callback to be called when a log entry would populated.
 */
void sr_log_set_cb(sr_log_cb log_callback);

/** @} logging */

////////////////////////////////////////////////////////////////////////////////
// Connection / Session Management
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup conn_sess_api Connection and Session API
 * @{
 */

/**
 * @brief Connects to the sysrepo datastore.
 *
 * @note Do not use `fork(2)` after creating a connection. Sysrepo internally stores the connection
 * ID of every connection. Forking will duplicate the connection and ID resulting in a mismatch.
 *
 * @param[in] opts Connection options.
 * @param[out] conn Created connection.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_connect(const sr_conn_options_t opts, sr_conn_ctx_t **conn);

/**
 * @brief Disconnect from the sysrepo datastore.
 *
 * Cleans up and frees connection context allocated by ::sr_connect. All sessions and subscriptions
 * started within the connection will be automatically stopped and cleaned up too.
 *
 * @note On error the function should be retried and must eventually succeed.
 *
 * @param[in] conn Connection acquired with ::sr_connect call to free.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_disconnect(sr_conn_ctx_t *conn);

/**
 * @brief Get the _libyang_ context used by a connection. Can be used in an application for working with data
 * and schemas.
 *
 * @note This context **must not** be changed. Also, to prevent the context from being destroyed by sysrepo,
 * it is locked and after no longer needing the context ::sr_release_context() must be called. Otherwise,
 * API functions changing the context will fail with time out.
 *
 * @param[in] conn Connection to use.
 * @return Const libyang context.
 */
const struct ly_ctx *sr_acquire_context(sr_conn_ctx_t *conn);

/**
 * @brief Get the _libyang_ context used by a connection. Can be used in an application for working with data
 * and schemas.
 *
 * Similar to and interchangeable with ::sr_acquire_context().
 *
 * @param[in] session Session whose connection to use.
 * @return Const libyang context.
 */
const struct ly_ctx *sr_session_acquire_context(sr_session_ctx_t *session);

/**
 * @brief Release _libyang_ context obtained from a session/connection.
 *
 * @note Must be called for each ::sr_acquire_context() call.
 *
 * @param[in] conn Connection to use.
 */
void sr_release_context(sr_conn_ctx_t *conn);

/**
 * @brief Release _libyang_ context obtained from a session/connection.
 *
 * Similar to and interchangeable with ::sr_release_context().
 *
 * @param[in] session Session whose connection to use.
 */
void sr_session_release_context(sr_session_ctx_t *session);

/**
 * @brief Get content ID of the current YANG module set. It conforms to the requirements for ietf-yang-library
 * "content-id" node value.
 *
 * @param[in] conn Connection to use.
 * @return Content ID.
 */
uint32_t sr_get_content_id(sr_conn_ctx_t *conn);

/**
 * @brief Get loaded plugins of a connection.
 *
 * @param[in] conn Connection to use.
 * @param[out] ds_plugins Optional pointer to array of datastore plugins ended by NULL.
 * @param[out] ntf_plugins Optional pointer to array of notification plugins ended by NULL.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_plugins(sr_conn_ctx_t *conn, const char ***ds_plugins, const char ***ntf_plugins);

/**
 * @brief Get the sysrepo SUPERUSER UID.
 *
 * @return Sysrepo SU UID.
 */
uid_t sr_get_su_uid(void);

/**
 * @brief Deprecated, use ::sr_discard_items().
 */
int sr_discard_oper_changes(sr_conn_ctx_t *conn, sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms);

/**
 * @brief Start a new session.
 *
 * @param[in] conn Connection to use.
 * @param[in] datastore Datastore on which to operate, can be later changed using
 * ::sr_session_switch_ds().
 * @param[out] session Created session.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_start(sr_conn_ctx_t *conn, const sr_datastore_t datastore, sr_session_ctx_t **session);

/**
 * @brief Stop the session and releases resources tied to it.
 *
 * Also releases any locks held and frees subscriptions created (only) by this session.
 *
 * @note On error the function should be retried and must eventually succeed.
 * Subscriptions, even if they no longer handle any events are **never** freed and
 * should be freed manually using ::sr_unsubscribe.
 *
 * @param[in] session Session to free.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_stop(sr_session_ctx_t *session);

/**
 * @brief Unsubscribe all subscriptions created by this session.
 *
 * @note Subscriptions, even if they no longer handle any events are **never** freed
 * and should be freed manually using ::sr_unsubscribe.
 *
 * @param[in] session Session to use.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_unsubscribe(sr_session_ctx_t *session);

/**
 * @brief Use notification buffering for the session.
 *
 * When a notification is sent using this session for
 * a module that supports replay (notification should be stored),
 * the notification function does not wait until it is stored
 * but delegates this work to a special thread and returns.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) whose notifications will be buffered.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_notif_buffer(sr_session_ctx_t *session);

/**
 * @brief Change datastore which the session operates on. All subsequent
 * calls will be issued on the chosen datastore. Previous calls are not
 * affected.
 *
 * @param[in] session Session to modify.
 * @param[in] ds New datastore that will be operated on.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_switch_ds(sr_session_ctx_t *session, sr_datastore_t ds);

/**
 * @brief Learn the datastore a session operates on.
 *
 * @param[in] session Session to use.
 * @return Datastore of the session.
 */
sr_datastore_t sr_session_get_ds(sr_session_ctx_t *session);

/**
 * @brief Set event originator name used for all events sent on this session.
 * It can then be read from the implicit event session in the callbacks using ::sr_session_get_orig_name().
 * This name should be used for interpreting the data set by ::sr_session_push_orig_data().
 *
 * The following originator names are well-known:
 *
 * - `netopeer2` for the [NETCONF server](https://github.com/CESNET/Netopeer2/#sysrepo-callbacks)
 * - `rousette` for the [RESTCONF server](https://github.com/CESNET/rousette)
 * - `sysrepo-cli` for the direct sysrepo mode of the [interactive CLI](https://github.com/CESNET/netconf-cli)
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] orig_name Arbitrary originator name.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_set_orig_name(sr_session_ctx_t *session, const char *orig_name);

/**
 * @brief Get event originator name.
 *
 * @param[in] session Implicit session provided in a callback.
 * @return Originator name if set, empty string "" otherwise.
 */
const char *sr_session_get_orig_name(sr_session_ctx_t *session);

/**
 * @brief Push (add) another chunk of event originator data used for all events sent on this session.
 * Its meaning is specific to the originator name (which must be [set](@ref sr_session_set_orig_name)
 * prior to calling this function) and can be read from the implicit event session in the callbacks
 * using ::sr_session_get_orig_data().
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] size Size of the @p data chunk.
 * @param[in] data Pointer to an opaque data chunk.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_push_orig_data(sr_session_ctx_t *session, uint32_t size, const void *data);

/**
 * @brief Remove all pushed event originator data.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 */
void sr_session_del_orig_data(sr_session_ctx_t *session);

/**
 * @brief Get a specific chunk of event originator data in a callback.
 *
 * @param[in] session Implicit session provided in a callback.
 * @param[in] idx Index of the data chunk, starts at 0.
 * @param[out] size Optional size of the @p data chunk.
 * @param[out] data Pointer to an opaque data chunk.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_get_orig_data(sr_session_ctx_t *session, uint32_t idx, uint32_t *size, const void **data);

/**
 * @brief Retrieve information about the error that has occurred
 * during the last operation executed within provided session.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[out] error_info Detailed error information. Be aware that
 * returned pointer may change by the next API call executed within the provided
 * session. Do not free or modify returned values.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_get_error(sr_session_ctx_t *session, const sr_error_info_t **error_info);

/**
 * @brief Copy the first error (if any) from a session to a callback session.
 *
 * @param[in] src_session Session (not [DS](@ref sr_datastore_t)-specific) to read the error from.
 * @param[in] trg_session Implicit session provided in a callback.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_dup_error(sr_session_ctx_t *src_session, sr_session_ctx_t *trg_session);

/**
 * @brief Set an error message for a failed callback communicated back to the originator.
 * Does not print the message.
 *
 * @note Intended for diff-check, change, RPC/action, or operational callbacks to be used
 * on the provided session.
 *
 * @param[in] session Implicit session provided in a callback.
 * @param[in] format Human-readable format of the error message.
 * @param[in] ... Format parameters.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_set_error_message(sr_session_ctx_t *session, const char *format, ...);

/**
 * @brief Set error data format identifier for a failed callback communicated back to the originator.
 * This format name should be used for interpreting the error data set by ::sr_session_push_error_data().
 *
 * There are some well-known error formats defined and those errors can be written/read using
 * [helper utility functions](@ref utils_error_format).
 *
 * @param[in] session Implicit session provided in a callback.
 * @param[in] error_format Arbitrary error format identifier.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_set_error_format(sr_session_ctx_t *session, const char *error_format);

/**
 * @brief Push (add) another chunk of error data for a failed callback communicated back to the originator.
 * Its meaning is specific to the error data format (which must be set prior to calling this function) identifier and
 * can be read from the error structure by the originator using ::sr_get_error_data().
 *
 * @param[in] session Implicit session provided in a callback.
 * @param[in] size Size of the error @p data chunk.
 * @param[in] data Pointer to an opaque error data chunk.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_push_error_data(sr_session_ctx_t *session, uint32_t size, const void *data);

/**
 * @brief Get a specific chunk of error data.
 *
 * If the error is a well-known one, it is possible to use [helper utility functions](@ref utils_error_format)
 * instead of repeatedly calling this function.
 *
 * @param[in] err Error structure to use.
 * @param[in] idx Index of the error data chunk, starts at 0.
 * @param[out] size Optional size of the error @p data chunk.
 * @param[out] data Pointer to an opaque error data chunk.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_error_data(const sr_error_info_err_t *err, uint32_t idx, uint32_t *size, const void **data);

/**
 * @brief Return the assigned session ID of the sysrepo session.
 *
 * @param [in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @return sysrepo SID or 0 in case of error.
 */
uint32_t sr_session_get_id(sr_session_ctx_t *session);

/**
 * @brief Set the effective user of a session to a different one than the process owner.
 *
 * Required SUPERUSER access.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to change.
 * @param[in] user System user.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_session_set_user(sr_session_ctx_t *session, const char *user);

/**
 * @brief Get the effective user of a session.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @return Session user.
 */
const char *sr_session_get_user(sr_session_ctx_t *session);

/**
 * @brief Get the connection the session was created on.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @return Sysrepo connection.
 */
sr_conn_ctx_t *sr_session_get_connection(sr_session_ctx_t *session);

/** @} connsess */

////////////////////////////////////////////////////////////////////////////////
// Schema Manipulation API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup schema_api Schema API
 * @{
 */

/**
 * @brief Get the common path prefix for all sysrepo files.
 *
 * @note If a specific path was changed during compilation, it does not use this
 * path prefix.
 *
 * @return Sysrepo repository path.
 */
const char *sr_get_repo_path(void);

/**
 * @brief Install a new schema (module) into sysrepo.
 *
 * For all datastores and notifications the default plugins are used.
 *
 * @param[in] conn Connection to use.
 * @param[in] schema_path Path to the new schema. Can have either YANG or YIN extension/format.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @param[in] features Optional array of enabled features ended with NULL. Feature '*' enables them all.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_install_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features);

/**
 * @brief Install a new schema (module) into sysrepo with all the available options.
 *
 * Any initial data are also used as factory-default datastore data.
 *
 * @param[in] conn Connection to use.
 * @param[in] schema_path Path to the new schema. Can have either YANG or YIN extension/format.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @param[in] features Optional array of enabled features ended with NULL, all disabled by default. Feature '*' enables
 * them all.
 * @param[in] module_ds Optional datastore implementation plugin names for each datastore, NULL for all defaults.
 * If only ::SR_DS_RUNNING plugin name is NULL, it is disabled and effectively always mirrors ::SR_DS_STARTUP.
 * @param[in] owner Optional initial owner of the module data, process user by default.
 * @param[in] group Optional initial group of the module data, process group by default.
 * @param[in] perm Optional initial permissions of the module data, otherwise system defaults are applied.
 * @param[in] data Optional initial data in @p format to set, only if @p data_path is not set.
 * @param[in] data_path Optional path to an initial data file in @p format to set, only if @p data is not set.
 * @param[in] format Format of @p data or @p data_path file.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_install_module2(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs, const char **features,
        const sr_module_ds_t *module_ds, const char *owner, const char *group, mode_t perm, const char *data,
        const char *data_path, LYD_FORMAT format);

/**
 * @brief Install new schemas (modules) into sysrepo in a batch.
 *
 * For all datastores and notifications the default plugins are used.
 *
 * @param[in] conn Connection to use.
 * @param[in] schema_paths Array of paths to the new schemas terminated by NULL. Can have either YANG or YIN extension/format.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @param[in] features Array of the same length as @p schema_paths (minus the last NULL). Each item is an array of
 * enabled features ended with NULL for the @p schema_paths on the same index. Can be NULL for leaving all
 * the features disabled.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_install_modules(sr_conn_ctx_t *conn, const char **schema_paths, const char *search_dirs,
        const char ***features);

/**
 * @brief Install new schemas (modules) into sysrepo in a batch with all the available options.
 *
 * Any initial data are also used as factory-default datastore data.
 *
 * @param[in] conn Connection to use.
 * @param[in] modules Array of new modules to be installed with all their information.
 * @param[in] module_count Count of @p modules.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @param[in] data Optional initial data of all the modules in @p format to set, only if @p data_path is not set.
 * @param[in] data_path Optional path to an initial data file of all the modules in @p format to set, only if @p data
 * is not set.
 * @param[in] format Format of @p data or @p data_path file.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_install_modules2(sr_conn_ctx_t *conn, const sr_install_mod_t *modules, uint32_t module_count,
        const char *search_dirs, const char *data, const char *data_path, LYD_FORMAT format);

/**
 * @brief Remove an installed module from sysrepo.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to remove.
 * @param[in] force If there are other installed modules depending on @p module_name, remove them, too.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_remove_module(sr_conn_ctx_t *conn, const char *module_name, int force);

/**
 * @brief Remove installed modules from sysrepo.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_names Array of names of modules to remove terminated by NULL.
 * @param[in] force If there are other installed modules depending on @p module_names, remove them, too.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_remove_modules(sr_conn_ctx_t *conn, const char **module_names, int force);

/**
 * @brief Update an installed schema (module) to a new revision.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] schema_path Path to the updated schema. Can have either YANG or YIN extension/format.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_update_module(sr_conn_ctx_t *conn, const char *schema_path, const char *search_dirs);

/**
 * @brief Update installed schemas (modules) to new revisions in a batch.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] schema_paths Array of paths to the new schemas terminated by NULL. Can have either YANG or YIN extension/format.
 * @param[in] search_dirs Optional search directories for import schemas, supports the format `<dir>[:<dir>]*`.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_update_modules(sr_conn_ctx_t *conn, const char **schema_paths, const char *search_dirs);

/**
 * @brief Change module replay support.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to change. NULL to change all the modules.
 * @param[in] enable 0 to disable, non-zero to enable.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_set_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, int enable);

/**
 * @brief Learn replay support of a module.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to check.
 * @param[out] earliest_notif Optional timestamp of the earliest stored notification, zeroed if none are stored. Can
 * be set even if @p enabled is false when replay was enabled in the past.
 * @param[out] enabled Whether replay support is enabled or disabled.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, struct timespec *earliest_notif,
        int *enabled);

/**
 * @brief Change module permissions.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to change, NULL for all the modules.
 * @param[in] mod_ds Affected datastore, ::sr_datastore_t value or ::SR_MOD_DS_NOTIF.
 * @param[in] owner Optional, new owner of the module.
 * @param[in] group Optional, new group of the module.
 * @param[in] perm Optional, new permissions of the module.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_set_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, const char *owner,
        const char *group, mode_t perm);

/**
 * @brief Learn about module permissions.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to use.
 * @param[in] mod_ds Affected datastore, ::sr_datastore_t value or ::SR_MOD_DS_NOTIF.
 * @param[out] owner Optional, read the owner of the module.
 * @param[out] group Optional, read the group of the module.
 * @param[out] perm Optional, read the permissions of the module.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, char **owner, char **group,
        mode_t *perm);

/**
 * @brief Check whether the current application has read/write access to a module.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to use.
 * @param[in] mod_ds Affected datastore, ::sr_datastore_t value or ::SR_MOD_DS_NOTIF.
 * @param[out] read Optional, set if read access was granted.
 * @param[out] write Optional, set if write access was granted.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_check_module_ds_access(sr_conn_ctx_t *conn, const char *module_name, int mod_ds, int *read, int *write);

/**
 * @brief Enable a module feature.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to change.
 * @param[in] feature_name Name of the feature to enable.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_enable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name);

/**
 * @brief Disable a module feature.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module to change.
 * @param[in] feature_name Name of the feature to disable.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_disable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name);

/**
 * @brief Get internal sysrepo data tree, which holds detailed information about installed modules. It should
 * not be needed except for some specific use-cases. These data are from the _sysrepo_ module found in
 * `modules/sysrepo.yang`.
 *
 * @param[in] conn Connection to use.
 * @param[out] sysrepo_data Sysrepo internal data tree.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_module_info(sr_conn_ctx_t *conn, sr_data_t **sysrepo_data);

/**
 * @brief Check whether a module is an internal *libyang* or *sysrepo* module. Evaluates to true
 * for all the modules that are installed by default when no modules were explicitly added.
 *
 * @param[in] ly_mod Module to check.
 * @return true (0) for an internal module.
 * @return false (non-zero) for other modules.
 */
int sr_is_module_internal(const struct lys_module *ly_mod);

/** @} schema */

////////////////////////////////////////////////////////////////////////////////
// Data Retrieval API (get / get-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup get_data_api Getting Data API
 * @{
 */

/**
 * @brief Retrieve a single data element selected by the provided path.
 * Data are represented as ::sr_val_t structures.
 *
 * If the path identifies an empty leaf, a list or a container, the value
 * has no data filled in and its type is set properly
 * (::SR_LEAF_EMPTY_T / ::SR_LIST_T / ::SR_CONTAINER_T / ::SR_CONTAINER_PRESENCE_T).
 *
 * Required READ access, but if the access check fails, the module data are simply ignored without an error.
 *
 * @see Use ::sr_get_items for retrieving larger chunks
 * of data from the datastore. Since it retrieves the data from datastore in
 * larger chunks, it can work much more efficiently than multiple ::sr_get_item calls.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) of the data element to be retrieved.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @param[out] value Requested node, allocated dynamically (free using ::sr_free_val).
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if multiple nodes match the path,
 * ::SR_ERR_NOT_FOUND if no nodes match the path).
 */
int sr_get_item(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_val_t **value);

/**
 * @brief Retrieve an array of data elements selected by the provided XPath.
 * Data are represented as ::sr_val_t structures.
 *
 * All data elements are transferred within one message from the datastore,
 * which is more efficient that calling multiple ::sr_get_item calls.
 *
 * Required READ access, but if the access check fails, the module data are simply ignored without an error.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] xpath [XPath](@ref paths) of the data elements to be retrieved.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @param[in] opts Options overriding default get behaviour.
 * @param[out] values Array of requested nodes, if any, allocated dynamically (free using ::sr_free_values).
 * @param[out] value_cnt Number of returned elements in the values array.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_items(sr_session_ctx_t *session, const char *xpath, uint32_t timeout_ms, const sr_get_options_t opts,
        sr_val_t **values, size_t *value_cnt);

/**
 * @brief Acquire libyang data tree together with its context lock in a SR data structure.
 *
 * Before a libyang data tree used in sysrepo can be created, ::sr_acquire_context() must be called
 * to get the connection context. If the created libyang data tree is then passed to this function,
 * it will handle the full cleanup of releasing the context and freeing the data.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] tree libyang data tree, ownership is passed to @p data in all cases.
 * @param[out] data Created SR data, free with ::sr_release_data().
 * @return Error code (::SR_ERR_OK on success), even on error @p tree is freed and context released.
 */
int sr_session_acquire_data(sr_session_ctx_t *session, struct lyd_node *tree, sr_data_t **data);

/**
 * @brief Acquire libyang data tree together with its context lock in a SR data structure.
 *
 * Similar functionality as ::sr_session_acquire_data().
 *
 * @param[in] conn Connection to use.
 * @param[in] tree libyang data tree, ownership is passed to @p data in all cases.
 * @param[out] data Created SR data, free with ::sr_release_data().
 * @return Error code (::SR_ERR_OK on success), even on error @p tree is freed and context released.
 */
int sr_acquire_data(sr_conn_ctx_t *conn, struct lyd_node *tree, sr_data_t **data);

/**
 * @brief Retrieve a single subtree whose root node is selected by the provided path.
 * Data are represented as _libyang_ subtrees.
 *
 * The functions returns values and all associated information stored under the root node and
 * all its descendants. While the same data can be obtained using ::sr_get_items in combination
 * with the expressive power of XPath addressing, the recursive nature of the output data type
 * also preserves the hierarchical relationships between data elements.
 *
 * Required READ access, but if the access check fails, the module data are simply ignored without an error.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) selecting the root node of the subtree to be retrieved.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @param[out] subtree SR data with the requested subtree. NULL if none found.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if multiple nodes match the path,
 * ::SR_ERR_NOT_FOUND if path is invalid - no nodes will ever match it).
 */
int sr_get_subtree(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_data_t **subtree);

/**
 * @brief Retrieve a tree whose root nodes match the provided XPath.
 * Data are represented as _libyang_ subtrees.
 *
 * Top-level trees are always returned so if an inner node is selected, all of its descendants
 * and its direct parents (lists also with keys) are returned.
 *
 * If the subtree selection process results in too many node overlaps, the cost of the operation
 * may be unnecessarily big. As an example, a common XPath expression `//.` is normally used
 * to select all nodes in a data tree, but for this operation it would result in an excessive duplication
 * of data nodes. Since all the descendants of each matched node are returned implicitly, `//` in the XPath
 * should never be used (i.e. `/\asterisk` is the correct XPath for all the nodes).
 *
 * Required READ access, but if the access check fails, the module data are simply ignored without an error.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] xpath [XPath](@ref paths) selecting root nodes of subtrees to be retrieved.
 * @param[in] max_depth Maximum depth of the selected subtrees. 0 is unlimited, 1 will not return any
 * descendant nodes. If a list should be returned, its keys are always returned as well.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @param[in] opts Options overriding default get behaviour.
 * @param[out] data SR data with connected top-level data trees of all the requested data. NULL if none found.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND if xpath is invalid - no nodes will ever match it).
 */
int sr_get_data(sr_session_ctx_t *session, const char *xpath, uint32_t max_depth, uint32_t timeout_ms,
        const sr_get_options_t opts, sr_data_t **data);

/**
 * @brief Retrieve a single value matching the provided XPath.
 * Data are represented as a single _libyang_ node.
 *
 * Compared to ::sr_get_data() or ::sr_get_subtree() this function is a bit more efficient because it returns
 * only the selected node which is *disconnected* from its parents.
 *
 * Required READ access, but if the access check fails, the module data are simply ignored without an error.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) of the data element to be retrieved.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @param[out] node SR data with the found node. NULL if none found.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_INVAL_ARG if multiple nodes match the path,
 * ::SR_ERR_NOT_FOUND if no nodes match the path).
 */
int sr_get_node(sr_session_ctx_t *session, const char *path, uint32_t timeout_ms, sr_data_t **node);

/**
 * @brief Release SR data structure, whoch consists of freeing the data tree, releasing the context,
 * and freeing the structure itself.
 *
 * @param[in] data SR data to release and free.
 */
void sr_release_data(sr_data_t *data);

/**
 * @brief Free ::sr_val_t structure and all memory allocated within it.
 *
 * @param[in] value Value to be freed.
 */
void sr_free_val(sr_val_t *value);

/**
 * @brief Free array of ::sr_val_t structures (and all memory allocated
 * within of each array element).
 *
 * @param[in] values Array of values to be freed.
 * @param[in] count Number of elements stored in the array.
 */
void sr_free_values(sr_val_t *values, size_t count);

/** @} getdata */

////////////////////////////////////////////////////////////////////////////////
// Data Manipulation API (edit-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup edit_data_api Editing Data API
 * @{
 */

/**
 * @brief Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
 * These changes are applied only after calling ::sr_apply_changes().
 * Data are represented as ::sr_val_t structures.
 *
 * With default options it recursively creates all missing nodes (containers and
 * lists including their key leaves) in the xpath to the specified node (can be
 * turned off with ::SR_EDIT_NON_RECURSIVE option). If ::SR_EDIT_STRICT flag is set,
 * the node must not exist (otherwise an error is returned). Neither option is allowed
 * for ::SR_DS_OPERATIONAL.
 *
 * To create a list use @p path with key values included in predicates, @p value will be ignored.
 * When creating key-less lists and state leaf-lists, use positional predicates such as `[1]` to refer to the instances.
 * Using no predicate means the instance should be created.
 *
 * The value of a leaf-list can be specified either by predicate in xpath or by value argument.
 * If both are present, value argument is ignored and xpath predicate is used.
 *
 * Edits preserve their order only if ::SR_EDIT_ISOLATE is used and in some cases it may
 * affect the result.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) identifier of the data element to be set.
 * @param[in] value Value to be set. `xpath` member of the ::sr_val_t structure can be NULL.
 * @param[in] opts Options overriding default behavior of this call.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_OPERATION_FAILED if the whole edit was discarded).
 */
int sr_set_item(sr_session_ctx_t *session, const char *path, const sr_val_t *value, const sr_edit_options_t opts);

/**
 * @brief Prepare to set (create) the value of a leaf, leaf-list, list, or presence container.
 * These changes are applied only after calling ::sr_apply_changes().
 * Data are represented as pairs of a path and string value.
 *
 * Function provides the same functionality as ::sr_set_item().
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) identifier of the data element to be set.
 * @param[in] value String representation of the value to be set.
 * @param[in] origin Origin of the value, used only for ::SR_DS_OPERATIONAL edits. Module ietf-origin is assumed
 * if no prefix used.
 * @param[in] opts Options overriding default behavior of this call.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_OPERATION_FAILED if the whole edit was discarded).
 */
int sr_set_item_str(sr_session_ctx_t *session, const char *path, const char *value, const char *origin,
        const sr_edit_options_t opts);

/**
 * @brief Prepare to delete the nodes matching the specified xpath. These changes are applied only
 * after calling ::sr_apply_changes(). The accepted values are the same as for ::sr_set_item_str.
 *
 * If ::SR_EDIT_STRICT flag is set the specified node must must exist in the datastore.
 * If the @p path includes the list keys/leaf-list value, the specified instance is deleted.
 * If the @p path of list/leaf-list does not include keys/value, all instances are deleted but there can be no further
 * changes merged into the list, use ::SR_EDIT_ISOLATE in such a case.
 *
 * For ::SR_DS_OPERATIONAL, the flag is not allowed. However, when trying to **remove a value stored in the push
 * operational data** (set before using ::sr_set_item_str() on ::SR_DS_OPERATIONAL, for example), use
 * ::sr_discard_items() instead.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) identifier of the data element to be deleted.
 * @param[in] opts Options overriding default behavior of this call.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_OPERATION_FAILED if the whole edit was discarded).
 */
int sr_delete_item(sr_session_ctx_t *session, const char *path, const sr_edit_options_t opts);

/**
 * @brief Deprecated, use ::sr_delete_item().
 */
int sr_oper_delete_item_str(sr_session_ctx_t *session, const char *path, const char *value, const sr_edit_options_t opts);

/**
 * @brief Prepare to discard nodes matching the specified xpath (or all if not set) previously set by the
 * session connection. Usable only for ::SR_DS_OPERATIONAL datastore. These changes are applied only
 * after calling ::sr_apply_changes().
 *
 * Creates an opaque node `discard-items` in the `sysrepo` YANG module namespace with @p xpath used as the value.
 * Such a node can be a part of the edit in ::sr_edit_batch() and will discard nodes like this function does.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] xpath [XPath](@ref paths) expression filtering the nodes to discard, all if NULL.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_discard_items(sr_session_ctx_t *session, const char *xpath);

/**
 * @brief Prepare to move/create the instance of an user-ordered list or leaf-list to the specified position.
 * These changes are applied only after calling ::sr_apply_changes().
 *
 * Item can be moved to the first or last position or positioned relatively to its sibling.
 *
 * With default options it recursively creates all missing nodes (containers and
 * lists including their key leaves) in the xpath to the specified node (can be
 * turned off with ::SR_EDIT_NON_RECURSIVE option). If ::SR_EDIT_STRICT flag is set,
 * the node must not exist (otherwise an error is returned).
 *
 * For ::SR_DS_OPERATIONAL, neither option is allowed.
 *
 * @note To determine current order, you can issue a ::sr_get_items() call
 * (without specifying keys of particular list).
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use
 * @param[in] path [Path](@ref paths) identifier of the data element to be moved.
 * @param[in] position Requested move direction.
 * @param[in] list_keys Predicate identifying the relative list instance (example input `[key1="val1"][key2="val2"]...`).
 * @param[in] leaflist_value Value of the relative leaf-list instance (example input `val1`) used
 * to determine relative position, needed only if position argument is ::SR_MOVE_BEFORE or ::SR_MOVE_AFTER.
 * @param[in] origin Origin of the value, used only for ::SR_DS_OPERATIONAL edits. Module ietf-origin is assumed
 * if no prefix used.
 * @param[in] opts Options overriding default behavior of this call.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_OPERATION_FAILED if the whole edit was discarded).
 */
int sr_move_item(sr_session_ctx_t *session, const char *path, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value, const char *origin, const sr_edit_options_t opts);

/**
 * @brief Provide a prepared edit data tree to be applied.
 * These changes are applied only after calling ::sr_apply_changes().
 *
 * Only operations `merge`, `remove`, and `ether` are allowed for ::SR_DS_OPERATIONAL.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] edit Edit content, similar semantics to
 * [NETCONF \<edit-config\>](https://tools.ietf.org/html/rfc6241#section-7.2) content. Uses @p edit and all of its
 * following siblings.
 * @param[in] default_operation Default operation for nodes without operation on themselves or any parent.
 * Possible values are `merge`, `replace`, or `none` (see [NETCONF RFC](https://tools.ietf.org/html/rfc6241#page-39)).
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation);

/**
 * @brief Perform the validation a datastore and any changes made in the current session, but do not
 * apply nor discard them.
 *
 * Provides only YANG validation, apply-changes **subscribers will not be notified** in this case.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name If specified, limits the validate operation only to this module and its dependencies.
 * @param[in] timeout_ms Operational callback timeout in milliseconds. If 0, default is used.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_validate(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms);

/**
 * @brief Apply changes made in the current session.
 * In case the changes could not be applied successfully for any reason,
 * they remain intact in the session.
 *
 * @note Note that in case that you are changing the _running_ datastore, you also
 * need to copy the config to _startup_ to make the changes persistent.
 *
 * Required WRITE access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to apply changes of.
 * @param[in] timeout_ms Change callback timeout in milliseconds. If 0, default is used. Note that this timeout
 * is measured separately for each callback meaning this whole function call can easily __take more time__ than this
 * timeout if there are changes applied for several subscribers.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_apply_changes(sr_session_ctx_t *session, uint32_t timeout_ms);

/**
 * @brief Learn whether there are any prepared non-applied changes in the session.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to check changes in.
 * @return non-zero if there are some changes, 0 if there are none.
 */
int sr_has_changes(sr_session_ctx_t *session);

/**
 * @brief Retrieve stored changes (prepared, not yet applied).
 *
 * Note: as soon as the changes get applied or discarded, the return value becomes invalid.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to retrieve changes from.
 * @return The stored changes, or NULL, if there are none.
 */
const struct lyd_node *sr_get_changes(sr_session_ctx_t *session);

/**
 * @brief Discard prepared changes made in the current session.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to discard changes from.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_discard_changes(sr_session_ctx_t *session);

/**
 * @brief Replace a datastore with the contents of a data tree. If the module is specified, limit
 * the operation only to the specified module. If it is not specified, the operation is performed on all modules.
 *
 * Required WRITE access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific - target datastore) to use.
 * @param[in] module_name If specified, limits the replace operation only to this module.
 * @param[in] src_config Source data to replace the datastore in @p session connection _libyang_ context.
 * Is ALWAYS spent and cannot be further used by the application!
 * @param[in] timeout_ms Configuration callback timeout in milliseconds. If 0, default is used.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_replace_config(sr_session_ctx_t *session, const char *module_name, struct lyd_node *src_config,
        uint32_t timeout_ms);

/**
 * @brief Replaces a conventional datastore with the contents of
 * another conventional datastore. If the module is specified, limits
 * the operation only to the specified module. If it is not specified,
 * the operation is performed on all modules.
 *
 * @note Note that copying from _candidate_ to _running_ or vice versa causes
 * the _candidate_ datastore to revert to original behavior of mirroring _running_ datastore (@ref datastores).
 *
 * Required WRITE access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific - target datastore) to use.
 * @param[in] module_name Optional module name that limits the copy operation only to this module.
 * @param[in] src_datastore Source datastore.
 * @param[in] timeout_ms Configuration callback timeout in milliseconds. If 0, default is used.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_copy_config(sr_session_ctx_t *session, const char *module_name, sr_datastore_t src_datastore, uint32_t timeout_ms);

/** @} editdata */

////////////////////////////////////////////////////////////////////////////////
// Locking API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup lock_api Locking API
 * @{
 */

/**
 * @brief Locks the data of the specified module or the whole datastore.
 *
 * @note Note that locking _candidate_ datastore after it has already
 * been modified is not allowed. Session needs to acquire this lock
 * before it or any other session performs any changes.
 *
 * @note This lock will be automatically released when the session is stopped.
 *
 * Required READ access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Optional name of the module to be locked.
 * @param[in] timeout_ms Timeout in milliseconds for waiting for the lock(s). If 0, no waiting is performed.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_lock(sr_session_ctx_t *session, const char *module_name, uint32_t timeout_ms);

/**
 * @brief Unlocks the data of the specified module or the whole datastore.
 *
 * Required READ access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Optional name of the module to be unlocked.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_unlock(sr_session_ctx_t *session, const char *module_name);

/**
 * @brief Check whether the data of the specified module or the whole datastore are locked.
 *
 * Note that if whole datastore is checked, @p is_locked will be set only if all
 * the modules are locked by the same Sysrepo session. If a module is not locked
 * or locked by another Sysrepo session, @p is_locked will be false.
 *
 * @param[in] conn Connection to use.
 * @param[in] datastore Datastore of the lock.
 * @param[in] module_name Optional name of the module to check.
 * @param[out] is_locked True is the module or whole datastore is locked.
 * @param[out] id Optional Sysrepo SID of the session if the module/datastore is locked.
 * @param[out] timestamp Optional timestamp of the lock.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_lock(sr_conn_ctx_t *conn, sr_datastore_t datastore, const char *module_name, int *is_locked, uint32_t *id,
        struct timespec *timestamp);

/** @} lock */

////////////////////////////////////////////////////////////////////////////////
// Subscription API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup subs_api Subscription API
 * @{
 */

/**
 * @brief Get the event pipe of a subscription. Do not call unless ::SR_SUBSCR_NO_THREAD flag was used
 * when subscribing! Event pipe can be used in `select()`, `poll()`, or similar functions to listen for new events.
 * It will then be ready for reading.
 *
 * @param[in] subscription Subscription without a listening thread.
 * @param[out] event_pipe Event pipe of the subscription, do not close! It will be closed
 * when the subscription is unsubscribed.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_event_pipe(sr_subscription_ctx_t *subscription, int *event_pipe);

/**
 * @brief Process any pending new events on a subscription. Should not be called unless ::SR_SUBSCR_NO_THREAD flag
 * was used when subscribing! Usually called after this subscription's event pipe is ready for reading but can
 * also be called periodically.
 *
 * @param[in] subscription Subscription without a listening thread with some new events.
 * @param[in] session Optional session for storing errors.
 * @param[out] wake_up_in Optional time when a scheduled event occurs and this function should be called again. It can
 * be the nearest notification subscription stop time or operational poll subscription cache update. If there are no
 * scheduled events in future, it is zeroed.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_process_events(sr_subscription_ctx_t *subscription, sr_session_ctx_t *session,
        struct timespec *wake_up_in);

/**
 * @brief Get the subscription ID of the last created subscription.
 *
 * @param[in] subscription Subscription context to read from.
 * @return Unique subscription ID.
 */
uint32_t sr_subscription_get_last_sub_id(const sr_subscription_ctx_t *subscription);

/**
 * @brief Learn the suspend state of a specific subscription.
 *
 * @param[in] subscription Subscription context to use.
 * @param[in] sub_id Subscription ID of the subscription to check.
 * @param[out] suspended Whether the subscription is suspended or not.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_get_suspended(sr_subscription_ctx_t *subscription, uint32_t sub_id, int *suspended);

/**
 * @brief Suspend a specific subscription.
 * Special ::SR_EV_NOTIF_SUSPENDED notification is delivered for suspended notification subscriptions.
 *
 * @param[in] subscription Subscription context to use.
 * @param[in] sub_id Subscription ID of the specific subscription to suspend.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_suspend(sr_subscription_ctx_t *subscription, uint32_t sub_id);

/**
 * @brief Resume a previously suspended subscription.
 * Special ::SR_EV_NOTIF_RESUMED notification is delivered for resumed notification subscriptions.
 *
 * @param[in] subscription Subscription context to use.
 * @param[in] sub_id Subscription ID of the specific subscription to resume.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_resume(sr_subscription_ctx_t *subscription, uint32_t sub_id);

/**
 * @brief Unsubscribe a specific or all the subscriptions in a subscription structure.
 *
 * If all subscriptions are being unsubscribed, the subscription structure can still be used normally
 * until ::sr_unsubscribe() is called, even if there are no actual subscriptions left in it. This
 * is useful for preventing dead locks if using the subscription in a custom event loop.
 *
 * @note On ::SR_ERR_TIME_OUT the function should be retried and must eventually succeed.
 *
 * @param[in] subscription Subscription context to use.
 * @param[in] sub_id Subscription ID of the subscription to unsubscribe, 0 for all the subscriptions.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_unsubscribe_sub(sr_subscription_ctx_t *subscription, uint32_t sub_id);

/**
 * @brief Suspend the default handler thread of a subscription structure.
 * Meaning it will stop handling any events on the subscription until it is resumed.
 *
 * @param[in] subscription Subscription context with a handler thread.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_thread_suspend(sr_subscription_ctx_t *subscription);

/**
 * @brief Resume the default handler thread of a subscription structure that was suspended previously.
 *
 * @param[in] subscription Subscription context with a handler thread.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_subscription_thread_resume(sr_subscription_ctx_t *subscription);

/**
 * @brief Unsubscribe all the subscriptions in a subscription structure and free it.
 *
 * @note On ::SR_ERR_TIME_OUT the function should be retried and must eventually succeed.
 *
 * @param[in] subscription Subscription context to free.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_unsubscribe(sr_subscription_ctx_t *subscription);

/** @} subs */

////////////////////////////////////////////////////////////////////////////////
// Change Subscriptions API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup change_subs_api Change Data Subscription API
 * @{
 */

/**
 * @brief Change the global priority of modules being notified about their changes. The default priority of every
 * module is 0 and modules with the same priority have their callbacks notified **simultaneously**.
 *
 * Example callback order for modules A, B, C with A having callbacks with priority 10, 5, and 0, module B with
 * callbacks 5, 4, and 3, and module C with 1, and 0. Simultaneously notified:
 * ```
 * A10, B5, C1;
 * A5, B4, C0;
 * A0, B3;
 * ```
 * As soon as a callback fails, its batch of callbacks is the last to be notified. Also note that the callbacks may
 * not actually be executed concurrently in case they are handled by a single subscription (thread).
 *
 * This order (of `running` datastore) is also used when initializing and copying data from `startup` to `running`
 * on SHM creation.
 *
 * Required WRITE access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module whose order to change.
 * @param[in] ds Affected datastore.
 * @param[in] priority New priority of the module, higher first.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_module_change_set_order(sr_conn_ctx_t *conn, const char *module_name, sr_datastore_t ds, uint32_t priority);

/**
 * @brief Get the current global priority of change subscriptions of a module.
 *
 * Required READ access.
 *
 * @param[in] conn Connection to use.
 * @param[in] module_name Name of the module whose order to get.
 * @param[in] ds Affected datastore.
 * @param[out] priority Priority of the module.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_module_change_get_order(sr_conn_ctx_t *conn, const char *module_name, sr_datastore_t ds, uint32_t *priority);

/**
 * @brief Subscribe for changes made in the specified module.
 *
 * The order of callbacks of a **single** module is determined by their @p priority. The order of **modules**
 * being notified is determined by their priority which can be adjusted by ::sr_module_change_set_order().
 *
 * Required WRITE access. If ::SR_SUBSCR_PASSIVE is set, required READ access.
 *
 * @param[in] session Session ([DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Name of the module of interest for change notifications.
 * @param[in] xpath Optional [XPath](@ref paths) further filtering the changes that will be handled by this subscription.
 * @param[in] callback Callback to be called when the change in the datastore occurs.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] priority Specifies the order in which the callbacks (**within module**) will be called, higher first.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_module_change_cb callback, void *private_data, uint32_t priority, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription);

/**
 * @brief Get information about an existing change subscription.
 *
 * @param[in] subscription Subscription structure to use.
 * @param[in] sub_id Subscription ID of the specific subscription.
 * @param[out] module_name Optional name of the module whose changes were subscribed.
 * @param[out] ds Optional datastore of the subscription.
 * @param[out] xpath Optional [XPath](@ref paths) filter of the subscription.
 * @param[out] filtered_out Optional number of filtered-out change events of the subscription.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_module_change_sub_get_info(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char **module_name,
        sr_datastore_t *ds, const char **xpath, uint32_t *filtered_out);

/**
 * @brief Modify an existing change subscription by changing its XPath filter.
 *
 * @param[in] subscription Subscription structure to use.
 * @param[in] sub_id Subscription ID of the specific subscription to modify.
 * @param[in] xpath New XPath filter to use by the subscription.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_module_change_sub_modify_xpath(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char *xpath);

/**
 * @brief Create an iterator for retrieving the changes (list of newly added / removed / modified nodes)
 * in module-change callbacks. It __cannot__ be used outside the callback.
 *
 * @see ::sr_get_change_next for iterating over the changeset using this iterator.
 *
 * @param[in] session Implicit session provided in the callbacks (::sr_module_change_cb). Will not work with other sessions.
 * @param[in] xpath [XPath](@ref paths) selecting the changes. Note that you must select all the changes specifically,
 * not just subtrees (to get a full change subtree `//.` can be appended to the XPath)! Also note that if you use
 * an XPath that selects more changes than subscribed to, you may actually get them because all the changes of a module
 * are available in every callback!
 * @param[out] iter Iterator context that can be used to retrieve individual changes using
 * ::sr_get_change_next calls. Allocated by the function, should be freed with ::sr_free_change_iter.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter);

/**
 * @brief Create an iterator for retrieving the changes (list of newly added / removed / modified nodes)
 * in module-change callbacks. It __can__ be used even outside the callback.
 *
 * @see ::sr_get_change_next for iterating over the changeset using this iterator.
 *
 * @param[in] session Implicit session provided in the callbacks (::sr_module_change_cb). Will not work with other sessions.
 * @param[in] xpath [XPath](@ref paths) selecting the changes. Note that you must select all the changes specifically,
 * not just subtrees (to get a full change subtree `//.` can be appended to the XPath)! Also note that if you use
 * an XPath that selects more changes than subscribed to, you may actually get them because all the changes of a module
 * are available in every callback!
 * @param[out] iter Iterator context that can be used to retrieve individual changes using
 * ::sr_get_change_next calls. Allocated by the function, should be freed with ::sr_free_change_iter.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_dup_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter);

/**
 * @brief Return the next change from the provided iterator created
 * by ::sr_get_changes_iter call. Data are represented as ::sr_val_t structures.
 *
 * @note If the operation is ::SR_OP_MOVED the meaning of new_value and old value argument is
 * as follows - the value pointed by new_value was moved after the old_value. If the
 * old value is NULL it was moved to the first position. The same applies for operation ::SR_OP_CREATED
 * if the created instance was a user-ordered (leaf-)list.
 *
 * @param[in] session Implicit session provided in the callbacks (::sr_module_change_cb). Will not work with other sessions.
 * @param[in,out] iter Iterator acquired with ::sr_get_changes_iter call.
 * @param[out] operation Type of the operation made on the returned item.
 * @param[out] old_value Old value of the item (the value before the change).
 * NULL in case that the item has been just created (operation ::SR_OP_CREATED).
 * @param[out] new_value New (modified) value of the the item. NULL in case that
 * the item has been just deleted (operation ::SR_OP_DELETED).
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND on no more changes).
 */
int sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value);

/**
 * @brief Returns the next change from the provided iterator created
 * by ::sr_get_changes_iter call. Data are represented as _libyang_ subtrees.
 *
 * @note Meaning of output parameters varies based on the operation:
 * ::SR_OP_CREATED - @p node is the created node, for user-ordered lists either @p prev_value or @p prev_list is
 * always set with meaning similar to ::SR_OP_MOVED.
 * ::SR_OP_MODIFIED - @p node is the modified node, @p prev_value is set to the previous value of the leaf,
 * @p prev_dflt is set if the previous leaf value was the default.
 * ::SR_OP_DELETED - @p node is the deleted node.
 * ::SR_OP_MOVED - @p node is the moved (leaf-)list instance, for user-ordered lists either @p prev_value (leaf-list) or
 * @p prev_list (list) is set to the preceding instance unless the node is the first, when they are set to "" (empty string).
 *
 * @param[in] session Implicit session provided in the callbacks (::sr_module_change_cb). Will not work with other sessions.
 * @param[in,out] iter Iterator acquired with ::sr_get_changes_iter call.
 * @param[out] operation Type of the operation made on the returned item.
 * @param[out] node Affected data node always with all parents, depends on the operation.
 * @param[out] prev_value Previous value, depends on the operation, may be NULL.
 * @param[out] prev_list Previous list keys predicate (`[key1="val1"][key2="val2"]...`), depends on the operation, may be NULL.
 * @param[out] prev_dflt Previous value default flag, depends on the operation, may be NULL.
 * @return Error code (::SR_ERR_OK on success, ::SR_ERR_NOT_FOUND on no more changes).
 */
int sr_get_change_tree_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        const struct lyd_node **node, const char **prev_value, const char **prev_list, int *prev_dflt);

/**
 * @brief Frees ::sr_change_iter_t iterator and all memory allocated within it.
 *
 * @param[in] iter Iterator to be freed.
 */
void sr_free_change_iter(sr_change_iter_t *iter);

/**
 * @brief Get the changes directly in the form of a diff in module-change callbacks.
 * It __cannot__ be used outside the callback.
 *
 * @param[in] session Implicit session provided in the callbacks (::sr_module_change_cb). Will not work with other sessions.
 * @return Const diff data tree, must not be modified.
 */
const struct lyd_node *sr_get_change_diff(sr_session_ctx_t *session);

/** @} datasubs */

////////////////////////////////////////////////////////////////////////////////
// RPC (Remote Procedure Calls) and Action API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup rpc_subs_api RPC/Action Subscription API
 * @{
 */

/**
 * @brief Subscribe for the delivery of an RPC/action. Data are represented as ::sr_val_t structures.
 *
 * Required WRITE access.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] xpath [XPath](@ref paths) identifying the RPC/action. Any predicates are allowed.
 * @param[in] callback Callback to be called.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] priority Specifies the order in which the callbacks (**within RPC/action**) will be called, higher first.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, void *private_data,
        uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribe for the delivery of an RPC/action. Data are represented as _libyang_ subtrees.
 *
 * Required WRITE access.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] xpath [XPath](@ref paths) identifying the RPC/action. Any predicates are allowed.
 * @param[in] callback Callback to be called.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] priority Specifies the order in which the callbacks (**within RPC/action**) will be called, higher first.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_rpc_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_rpc_tree_cb callback,
        void *private_data, uint32_t priority, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Send an RPC/action and wait for the result. Data are represented as ::sr_val_t structures.
 *
 * Required READ access.
 *
 * @note RPC/action must be valid in (is validated against) the [operational datastore](@ref oper_ds) context.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) identifying the RPC/action.
 * @param[in] input Array of input parameters (array of all nodes that hold some
 * data in RPC/action input subtree - same as ::sr_get_items would return).
 * @param[in] input_cnt Number of input parameters.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds. If 0, default is used.
 * @param[out] output Array of output parameters (all nodes that hold some data
 * in RPC/action output subtree). Will be allocated by sysrepo and should be freed by
 * caller using ::sr_free_values.
 * @param[out] output_cnt Number of output parameters.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_rpc_send(sr_session_ctx_t *session, const char *path, const sr_val_t *input, const size_t input_cnt,
        uint32_t timeout_ms, sr_val_t **output, size_t *output_cnt);

/**
 * @brief Send an RPC/action and wait for the result. Data are represented as _libyang_ subtrees.
 *
 * Required READ access.
 *
 * @note RPC/action must be valid in (is validated against) the [operational datastore](@ref oper_ds) context.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in,out] input Input data tree in @p session connection _libyang_ context, is validated.
 * @param[in] timeout_ms RPC/action callback timeout in milliseconds. If 0, default is used.
 * @param[out] output SR data with the output data tree.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_rpc_send_tree(sr_session_ctx_t *session, struct lyd_node *input, uint32_t timeout_ms, sr_data_t **output);

/** @} rpcsubs */

////////////////////////////////////////////////////////////////////////////////
// Notifications API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup notif_subs_api Notification Subscription API
 * @{
 */

/**
 * @brief Subscribe for the delivery of a notification(s). Data are represented as ::sr_val_t structures.
 *
 * Required WRITE access.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Name of the module whose notifications to subscribe to.
 * @param[in] xpath Optional [XPath](@ref paths) further filtering received notifications.
 * @param[in] start_time Optional start time of the subscription. Used for replaying stored notifications.
 * @param[in] stop_time Optional stop time ending the notification subscription.
 * @param[in] callback Callback to be called when the event notification is delivered.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        const struct timespec *start_time, const struct timespec *stop_time, sr_event_notif_cb callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribes for the delivery of a notification(s). Data are represented as _libyang_ subtrees.
 *
 * Required WRITE access.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Name of the module whose notifications to subscribe to.
 * @param[in] xpath Optional [XPath](@ref paths) further filtering received notifications.
 * @param[in] start_time Optional start time of the subscription. Used for replaying stored notifications.
 * @param[in] stop_time Optional stop time ending the notification subscription.
 * @param[in] callback Callback to be called when the event notification is delivered.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_subscribe_tree(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        const struct timespec *start_time, const struct timespec *stop_time, sr_event_notif_tree_cb callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Send a notification. Data are represented as ::sr_val_t structures. In case there are
 * particularly many notifications send on a session (100 notif/s or more) and all of them
 * are stored for replay, consider using ::sr_session_notif_buffer().
 *
 * Required WRITE access. If the module does not support replay, required READ access.
 *
 * @note Notification must be valid in (is validated against) the [operational datastore](@ref oper_ds) context.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] path [Path](@ref paths) identifying the notification.
 * @param[in] values Array of all nodes that hold some data in event notification subtree
 * (same as ::sr_get_items would return).
 * @param[in] values_cnt Number of items inside the values array.
 * @param[in] timeout_ms Notification callback timeout in milliseconds. If 0, default is used. Relevant only
 * if @p wait is set.
 * @param[in] wait Whether to wait until all (if any) notification callbacks were called (synchronous delivery)
 * or just publish the notification without waiting for its processing (asynchronous delivery).
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_send(sr_session_ctx_t *session, const char *path, const sr_val_t *values, const size_t values_cnt,
        uint32_t timeout_ms, int wait);

/**
 * @brief Send a notification. Data are represented as _libyang_ subtrees. In case there are
 * particularly many notifications send on a session (100 notif/s or more) and all of them
 * are stored for replay, consider using ::sr_session_notif_buffer().
 *
 * Required WRITE access. If the module does not support replay, required READ access.
 *
 * @note Notification must be valid in (is validated against) the [operational datastore](@ref oper_ds) context.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in,out] notif Notification data tree to send in @p session connection _libyang_ context, is validated.
 * @param[in] timeout_ms Notification callback timeout in milliseconds. If 0, default is used. Relevant only
 * if @p wait is set.
 * @param[in] wait Whether to wait until all (if any) notification callbacks were called (synchronous delivery)
 * or just publish the notification without waiting for its processing (asynchronous delivery).
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif, uint32_t timeout_ms, int wait);

/**
 * @brief Get information about an existing notification subscription.
 *
 * @param[in] subscription Subscription structure to use.
 * @param[in] sub_id Subscription ID of the specific subscription.
 * @param[out] module_name Optional name of the module whose notifications were subscribed.
 * @param[out] xpath Optional [XPath](@ref paths) filter of the subscription.
 * @param[out] start_time Optional start time of the subscription.
 * @param[out] stop_time Optional stop time of the subscription.
 * @param[out] filtered_out Optional number of filtered-out notifications of the subscription.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_sub_get_info(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char **module_name,
        const char **xpath, struct timespec *start_time, struct timespec *stop_time, uint32_t *filtered_out);

/**
 * @brief Modify an existing notification subscription by changing its XPath filter.
 * Special ::SR_EV_NOTIF_MODIFIED notification is delivered.
 *
 * @param[in] subscription Subscription structure to use.
 * @param[in] sub_id Subscription ID of the specific subscription to modify.
 * @param[in] xpath New XPath filter to use by the subscription.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_sub_modify_xpath(sr_subscription_ctx_t *subscription, uint32_t sub_id, const char *xpath);

/**
 * @brief Modify an existing notification subscription by changing its stop time.
 * Special ::SR_EV_NOTIF_MODIFIED notification is delivered.
 *
 * @param[in] subscription Subscription structure to use.
 * @param[in] sub_id Subscription ID of the specific subscription to modify.
 * @param[in] stop_time New stop time of the subscription, may be NULL for none.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_notif_sub_modify_stop_time(sr_subscription_ctx_t *subscription, uint32_t sub_id, const struct timespec *stop_time);

/** @} notifsubs */

////////////////////////////////////////////////////////////////////////////////
// Operational Data API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup oper_subs_api Operational Data Subscription API
 * @{
 */

/**
 * @brief Register for providing operational data at the given path.
 *
 * Usual behaviour is only ONE subscription for ONE XPath. When subscribing to the same XPath that was used in some
 * previous subscription, ::SR_SUBSCR_OPER_MERGE flag has to be used. Every subscription has its internal priority
 * based on the order in which they were subscribed. Priority influences merging the operational data from multiple
 * subscriptions with the same XPath. Operational data returned by later subscriptions overwrite the same data from any
 * previous subscriptions. When retrieving data all subscription callbacks with the same XPath are called
 * simultaneously (to achieve this, @p subscription should be different for each subscription so that there are
 * separate threads listening for each of the events).
 *
 * Required WRITE access.
 *
 * @note Be aware of some specific [threading limitations](@ref oper_subs).
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Name of the affected module.
 * @param[in] path [Path](@ref paths) identifying the subtree (not strictly required, all list/leaf-list instances
 * are also valid, for example) which the provider is able to provide. Predicates can be used to provide only
 * specific instances of nodes. Before calling this callback, any existing data matching this path __are deleted__
 * (unless modified by @p opts).
 * @param[in] callback Callback to be called when the operational data for the given xpath are requested.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_oper_get_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path,
        sr_oper_get_items_cb callback, void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Start periodic retrieval and caching of operational data at the given path.
 *
 * The operational data are cached in the connection of @p session. When any session created on this connection
 * requires data of the cached operational get subscription at @p path, the callback is not called and the cached data
 * are used instead. Additionally, if @p opts include ::SR_SUBSCR_OPER_POLL_DIFF, any changes detected on cache data
 * refresh are reported to corresponding subscribers. For an operational get subscription, there can only be a
 * __single__ operational poll subscription with this flag. The first cache update is performed directly by this
 * function.
 *
 * Required READ access.
 *
 * @note Be aware of some specific [threading limitations](@ref oper_subs). Especially note that you cannot have
 * an operational poll subscription in the same @p subscription structure as the operational get subscription being
 * cached because a dead-lock would occur on cache update.
 *
 * @param[in] session Session (not [DS](@ref sr_datastore_t)-specific) to use.
 * @param[in] module_name Name of the affected module.
 * @param[in] path [Path](@ref paths) matching the operational get subscription(s) to poll.
 * @param[in] valid_ms Time the retrieved data are stored in cache until being considered invalid.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context, zeroed for first subscription, freed by ::sr_unsubscribe.
 * @return Error code (::SR_ERR_OK on success).
 */
int sr_oper_poll_subscribe(sr_session_ctx_t *session, const char *module_name, const char *path, uint32_t valid_ms,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/** @} oper_subs */

////////////////////////////////////////////////////////////////////////////////
// sysrepo-plugind Plugin API
////////////////////////////////////////////////////////////////////////////////

/**
 * @defgroup srpd_plugin_api sysrepo-plugind Plugin API
 * @{
 */

/**
 * @brief sysrepo-plugind plugin initialization callback name that must exist in every plugin.
 *
 * The callback must be of ::srp_init_cb_t type.
 */
#define SRP_INIT_CB     "sr_plugin_init_cb"

/**
 * @brief sysrepo-plugind plugin cleanup callback name that must exist in every plugin.
 *
 * The callback must be of ::srp_cleanup_cb_t type.
 */
#define SRP_CLEANUP_CB  "sr_plugin_cleanup_cb"

/**
 * @brief Log a plugin error message and add the error into an error info structure.
 *
 * @param[in,out] err_info Empty or an exisiting error info to add to.
 * @param[in] plg_name Plugin name to print.
 * @param[in] error_format Optional arbitrary error format identifier, set its error data using
 * ::srplg_errinfo_push_error_data(). More details in ::sr_session_set_error_format().
 * @param[in] err_code Error code of the error.
 * @param[in] format Error message format.
 * @param[in] ... Error message format arguments.
 */
void srplg_log_errinfo(sr_error_info_t **err_info, const char *plg_name, const char *err_format_name,
        sr_error_t err_code, const char *format, ...) _FORMAT_PRINTF(5, 6);

/**
 * @brief Push (add) another chunk of error data for a failed plugin callback. Its meaning is specific to the error
 * data format name (which must be set prior to calling this function) identifier and can be read from the error
 * structure by the originator using ::sr_get_error_data().
 *
 * @param[in] err_info Error info created by ::srplg_log_errinfo() with a specific error format name set. The __last__
 * created error is being modified.
 * @param[in] size Size of the error @p data chunk.
 * @param[in] data Pointer to an opaque error data chunk.
 * @return Error code (::SR_ERR_OK on success).
 */
int srplg_errinfo_push_error_data(sr_error_info_t *err_info, uint32_t size, const void *data);

/**
 * @brief Free a superfluous error info.
 *
 * @param[in,out] err_info Error info to free, is set to NULL.
 */
void srplg_errinfo_free(sr_error_info_t **err_info);

/**
 * @brief Deprecated, use ::srplg_log_errinfo() instead.
 */
#define SRPLG_LOG_ERR(plg_name, ...) srplg_log(plg_name, SR_LL_ERR, __VA_ARGS__)

/**
 * @brief Log a plugin warning message with format arguments.
 *
 * @param[in] plg_name Plugin name to print.
 * @param[in] ... Format string and arguments.
 */
#define SRPLG_LOG_WRN(plg_name, ...) srplg_log(plg_name, SR_LL_WRN, __VA_ARGS__)

/**
 * @brief Log a plugin info message with format arguments.
 *
 * @param[in] plg_name Plugin name to print.
 * @param[in] ... Format string and arguments.
 */
#define SRPLG_LOG_INF(plg_name, ...) srplg_log(plg_name, SR_LL_INF, __VA_ARGS__)

/**
 * @brief Log a plugin debug message with format arguments.
 *
 * @param[in] plg_name Plugin name to print.
 * @param[in] ... Format string and arguments.
 */
#define SRPLG_LOG_DBG(plg_name, ...) srplg_log(plg_name, SR_LL_DBG, __VA_ARGS__)

/** @} srpd_plugin_api */

/**
 * @internal
 * @brief Log a plugin message with variable arguments.
 *
 * @param[in] plg_name Plugin name that is part of the message.
 * @param[in] ll Log level (severity).
 * @param[in] format Message format.
 * @param[in] ... Format arguments.
 */
void srplg_log(const char *plg_name, sr_log_level_t ll, const char *format, ...) _FORMAT_PRINTF(3, 4);

#ifdef __cplusplus
}
#endif

#endif /* _SYSREPO_H */
