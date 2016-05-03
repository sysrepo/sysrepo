/**
 * @file sysrepo.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Client Library public API.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#ifndef SYSREPO_H__
#define SYSREPO_H__

/**
 * @defgroup cl Client Library
 * @{
 *
 * @brief Provides the public API towards applications using sysrepo to store
 * their configuration data, or towards management agents.
 *
 * Communicates with Sysrepo Engine (@ref cm), which is running either inside
 * of dedicated sysrepo daemon, or within this library if daemon is not alive.
 *
 * Access to the sysrepo datastore is connection- and session- oriented. Before
 * calling any data access/manipulation API, one needs to connect to the datastore
 * via ::sr_connect and open a session via ::sr_session_start. One connection
 * can serve multiple sessions.
 *
 * Each data access/manipulation request call is blocking - blocks the connection
 * until the response from Sysrepo Engine comes, or until an error occurs. It is
 * safe to call multiple requests on the same session (or different session that
 * belongs to the same connection) from multiple threads at the same time,
 * however it is not effective, since each call is blocked until previous one
 * finishes. If you need fast multi-threaded access to sysrepo, use a dedicated
 * connection for each thread.
 *
 * @see
 * See @ref main_page "Sysrepo Introduction" for details about sysrepo architecture.
 * @see
 * @ref xp_page "XPath Addressing" is used for node identification in data-related calls.
 */

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>


////////////////////////////////////////////////////////////////////////////////
// Common typedefs and API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Sysrepo connection context used to identify a connection to sysrepo datastore.
 */
typedef struct sr_conn_ctx_s sr_conn_ctx_t;

/**
 * @brief Sysrepo session context used to identify a configuration session.
 */
typedef struct sr_session_ctx_s sr_session_ctx_t;

/**
 * @brief Possible types of an data element stored in the sysrepo datastore.
 */
typedef enum sr_type_e {
    /* special types that does not contain any data */
    SR_UNKNOWN_T,              /**< Element unknown to sysrepo (unsupported element). */

    SR_LIST_T,                 /**< List instance. ([RFC 6020 sec 7.8](http://tools.ietf.org/html/rfc6020#section-7.8)) */
    SR_CONTAINER_T,            /**< Non-presence container. ([RFC 6020 sec 7.5](http://tools.ietf.org/html/rfc6020#section-7.5)) */
    SR_CONTAINER_PRESENCE_T,   /**< Presence container. ([RFC 6020 sec 7.5.1](http://tools.ietf.org/html/rfc6020#section-7.5.1)) */
    SR_LEAF_EMPTY_T,           /**< A leaf that does not hold any value ([RFC 6020 sec 9.11](http://tools.ietf.org/html/rfc6020#section-9.11)) */
    SR_UNION_T,                /**< Choice of member types ([RFC 6020 sec 9.12](http://tools.ietf.org/html/rfc6020#section-9.12)) */

    /* types containing some data */
    SR_BINARY_T,       /**< Base64-encoded binary data ([RFC 6020 sec 9.8](http://tools.ietf.org/html/rfc6020#section-9.8)) */
    SR_BITS_T,         /**< A set of bits or flags ([RFC 6020 sec 9.7](http://tools.ietf.org/html/rfc6020#section-9.7)) */
    SR_BOOL_T,         /**< A boolean value ([RFC 6020 sec 9.5](http://tools.ietf.org/html/rfc6020#section-9.5)) */
    SR_DECIMAL64_T,    /**< 64-bit signed decimal number ([RFC 6020 sec 9.3](http://tools.ietf.org/html/rfc6020#section-9.3)) */
    SR_ENUM_T,         /**< A string from enumerated strings list ([RFC 6020 sec 9.6](http://tools.ietf.org/html/rfc6020#section-9.6)) */
    SR_IDENTITYREF_T,  /**< A reference to an abstract identity ([RFC 6020 sec 9.10](http://tools.ietf.org/html/rfc6020#section-9.10)) */
    SR_INSTANCEID_T,   /**< References a data tree node ([RFC 6020 sec 9.13](http://tools.ietf.org/html/rfc6020#section-9.13)) */
    SR_INT8_T,         /**< 8-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_INT16_T,        /**< 16-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_INT32_T,        /**< 32-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_INT64_T,        /**< 64-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_LEAFREF_T,      /**< A reference to a leaf instance ([RFC 6020 sec 9.9](http://tools.ietf.org/html/rfc6020#section-9.9)) */
    SR_STRING_T,       /**< Human-readable string ([RFC 6020 sec 9.4](http://tools.ietf.org/html/rfc6020#section-9.4)) */
    SR_UINT8_T,        /**< 8-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT16_T,       /**< 16-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT32_T,       /**< 32-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT64_T,       /**< 64-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
} sr_type_t;

/**
 * @brief Structure that contains value of an data element stored in the sysrepo datastore.
 */
typedef struct sr_val_s {
    /**
     * XPath identifier of the data element, as defined in
     * @ref xp_page "XPath Addressing" documentation or at
     * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
     */
    char *xpath;

    /** Type of an element. */
    sr_type_t type;

    /** Flag for default node (applicable only for leaves) */
    bool dflt;

    /** Data of an element (if applicable), properly set according to the type. */
    union {
        char *binary_val;       /**< Base64-encoded binary data ([RFC 6020 sec 9.8](http://tools.ietf.org/html/rfc6020#section-9.8)) */
        char *bits_val;         /**< A set of bits or flags ([RFC 6020 sec 9.7](http://tools.ietf.org/html/rfc6020#section-9.7)) */
        bool bool_val;          /**< A boolean value ([RFC 6020 sec 9.5](http://tools.ietf.org/html/rfc6020#section-9.5)) */
        double decimal64_val;   /**< 64-bit signed decimal number ([RFC 6020 sec 9.3](http://tools.ietf.org/html/rfc6020#section-9.3)) */
        char *enum_val;         /**< A string from enumerated strings list ([RFC 6020 sec 9.6](http://tools.ietf.org/html/rfc6020#section-9.6)) */
        char *identityref_val;  /**< A reference to an abstract identity ([RFC 6020 sec 9.10](http://tools.ietf.org/html/rfc6020#section-9.10)) */
        char *instanceid_val;   /**< References a data tree node ([RFC 6020 sec 9.13](http://tools.ietf.org/html/rfc6020#section-9.13)) */
        int8_t int8_val;        /**< 8-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        int16_t int16_val;      /**< 16-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        int32_t int32_val;      /**< 32-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        int64_t int64_val;      /**< 64-bit signed integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        char *leafref_val;      /**< A reference to a leaf instance ([RFC 6020 sec 9.9](http://tools.ietf.org/html/rfc6020#section-9.9)) */
        char *string_val;       /**< Human-readable string ([RFC 6020 sec 9.4](http://tools.ietf.org/html/rfc6020#section-9.4)) */
        uint8_t uint8_val;      /**< 8-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        uint16_t uint16_val;    /**< 16-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        uint32_t uint32_val;    /**< 32-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
        uint64_t uint64_val;    /**< 64-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    } data;
} sr_val_t;

/**
 * @brief Sysrepo error codes.
 */
typedef enum sr_error_e {
    SR_ERR_OK = 0,             /**< No error. */
    SR_ERR_INVAL_ARG,          /**< Invalid argument. */
    SR_ERR_NOMEM,              /**< Not enough memory. */
    SR_ERR_NOT_FOUND,          /**< Item not found. */
    SR_ERR_INTERNAL,           /**< Other internal error. */
    SR_ERR_INIT_FAILED,        /**< Sysrepo infra initialization failed. */
    SR_ERR_IO,                 /**< Input/Output error. */
    SR_ERR_DISCONNECT,         /**< The peer disconnected. */
    SR_ERR_MALFORMED_MSG,      /**< Malformed message. */
    SR_ERR_UNSUPPORTED,        /**< Unsupported operation requested. */
    SR_ERR_UNKNOWN_MODEL,      /**< Request includes unknown schema */
    SR_ERR_BAD_ELEMENT,        /**< Unknown element in existing schema */
    SR_ERR_VALIDATION_FAILED,  /**< Validation of the changes failed. */
    SR_ERR_COMMIT_FAILED,      /**< Commit operation failed. */
    SR_ERR_DATA_EXISTS,        /**< Item already exists. */
    SR_ERR_DATA_MISSING,       /**< Item does not exists. */
    SR_ERR_UNAUTHORIZED,       /**< Operation not authorized. */
    SR_ERR_LOCKED,             /**< Requested resource is already locked. */
    SR_ERR_TIME_OUT,           /**< Time out has expired. */
} sr_error_t;

/**
 * @brief Detailed sysrepo error information.
 */
typedef struct sr_error_info_s {
    const char *message;  /**< Error message. */
    const char *xpath;    /**< XPath to the node where the error has been discovered. */
} sr_error_info_t;

/**
 * @brief Returns the error message corresponding to the error code.
 *
 * @param[in] err_code Error code.
 *
 * @return Error message (statically allocated, do not free).
 */
const char *sr_strerror(int err_code);

/**
 * @brief Log levels used to determine if message of certain severity should be printed.
 */
typedef enum {
    SR_LL_NONE,  /**< Do not print any messages. */
    SR_LL_ERR,   /**< Print only error messages. */
    SR_LL_WRN,   /**< Print error and warning messages. */
    SR_LL_INF,   /**< Besides errors and warnings, print some other informational messages. */
    SR_LL_DBG    /**< Print all messages including some development debug messages. */
} sr_log_level_t;

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to
 * standard error output.
 *
 * By default, logging to stderr is disabled. Setting log level to any value
 * other than SR_LL_NONE enables the logging to stderr. Setting log level
 * back to SR_LL_NONE disables the logging to stderr.
 *
 * @param[in] log_level requested log level (verbosity).
 */
void sr_log_stderr(sr_log_level_t log_level);

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to system log.
 *
 * By default, logging into syslog is disabled. Setting log level to any value
 * other than SR_LL_NONE enables the logging into syslog. Setting log level
 * back to SR_LL_NONE disables the logging into syslog.
 *
 * @note Please note that enabling logging into syslog will overwrite your syslog
 * connection settings (calls openlog), if you are connected to syslog already.
 *
 * @param[in] log_level requested log level (verbosity).
 */
void sr_log_syslog(sr_log_level_t log_level);

/**
 * @brief Sets callback that will be called when a log entry would be populated.
 *
 * @param[in] level Verbosity level of the log entry.
 * @param[in] message Message of the log entry.
 */
typedef void (*sr_log_cb)(sr_log_level_t level, const char *message);

/**
 * @brief Sets callback that will be called when a log entry would be populated.
 * Callback will be called for each message with any log level.
 *
 * @param[in] log_callback Callback to be called when a log entry would populated.
 */
void sr_log_set_cb(sr_log_cb log_callback);


////////////////////////////////////////////////////////////////////////////////
// Connection / Session Management
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Flags used to override default connection handling by ::sr_connect call.
 */
typedef enum sr_conn_flag_e {
    SR_CONN_DEFAULT = 0,          /**< Default behavior - instantiate library-local Sysrepo Engine if
                                       the connection to sysrepo daemon is not possible. */
    SR_CONN_DAEMON_REQUIRED = 1,  /**< Require daemon connection - do not instantiate library-local Sysrepo Engine
                                       if the library cannot connect to the sysrepo daemon  (and return an error instead). */
    SR_CONN_DAEMON_START = 2,     /**< If sysrepo daemon is not running, and SR_CONN_DAEMON_REQUIRED was specified,
                                       start it (only if the process calling ::sr_connect is running under root privileges). */
} sr_conn_flag_t;

/**
 * @brief Options overriding default connection handling by ::sr_connect call,
 * can be bitwise OR-ed value of any ::sr_conn_flag_t flags.
 */
typedef uint32_t sr_conn_options_t;

/**
 * @brief Flags used to override default session handling (used by ::sr_session_start
 * and ::sr_session_start_user calls).
 */
typedef enum sr_session_flag_e {
    SR_SESS_DEFAULT = 0,      /**< Default (normal) session behavior. */
    SR_SESS_CONFIG_ONLY = 1,  /**< Session will process only configuration data (e.g. sysrepo won't
                                   return any state data by ::sr_get_items / ::sr_get_items_iter calls). */
} sr_session_flag_t;

/**
 * @brief Options overriding default connection session handling,
 * can be bitwise OR-ed value of any ::sr_session_flag_t flags.
 */
typedef uint32_t sr_conn_options_t;

/**
 * @brief Data stores that sysrepo supports. Both are editable via implicit candidate.
 * To make changes permanent in edited datastore ::sr_commit must be issued.
 * @see @ref ds_page "Datastores & Sessions" information page.
 */
typedef enum sr_datastore_e {
    SR_DS_STARTUP = 0,    /**< Contains configuration data that should be loaded by the controlled application when it starts. */
    SR_DS_RUNNING = 1,    /**< Contains currently applied configuration and state data of a running application.
                               @note This datastore is supported only by applications that subscribe for notifications about the changes made in the datastore. */
} sr_datastore_t;

/**
 * @brief Connects to the sysrepo datastore (Sysrepo Engine).
 *
 * @param[in] app_name Name of the application connecting to the datastore
 * (can be static string). Used only for accounting purposes.
 * @param[in] opts Options overriding default connection handling by this call.
 * @param[out] conn_ctx Connection context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_disconnect).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_connect(const char *app_name, const sr_conn_options_t opts, sr_conn_ctx_t **conn_ctx);

/**
 * @brief Disconnects from the sysrepo datastore (Sysrepo Engine).
 *
 * Cleans up and frees connection context allocated by ::sr_connect. All sessions
 * started within the connection will be automatically stopped and cleaned up too.
 *
 * @param[in] conn_ctx Connection context acquired with ::sr_connect call.
 */
void sr_disconnect(sr_conn_ctx_t *conn_ctx);

/**
 * @brief Starts a new configuration session.
 *
 * @see @ref ds_page "Datastores & Sessions" for more information about datastores and sessions.
 *
 * @param[in] conn_ctx Connection context acquired with ::sr_connect call.
 * @param[in] datastore Datastore on which all sysrepo functions within this
 * session will operate. Functionality of some sysrepo calls does not depend on
 * datastore. If your session will contain just calls like these, you can pass
 * any valid value (e.g. SR_RUNNING).
 * @param[in] opts Options overriding default session handling.
 * @param[out] session Session context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_session_stop).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_start(sr_conn_ctx_t *conn_ctx, const sr_datastore_t datastore,
        const sr_conn_options_t opts, sr_session_ctx_t **session);

/**
 * @brief Starts a new configuration session on behalf of a different user.
 *
 * This call is intended for northbound access to sysrepo from management
 * applications, that need sysrepo to authorize the operations not only
 * against the user under which the management application is running, but
 * also against another user (e.g. user that connected to the management application).
 *
 * @note Be aware that authorization of specified user may fail with unexpected
 * errors in case that the client library uses its own Sysrepo Engine at the
 * moment and your process in not running under root privileges. To prevent
 * this situation, consider specifying SR_CONN_DAEMON_REQUIRED flag by
 * ::sr_connect call or using ::sr_session_start instead of this function.
 *
 * @see @ref ds_page "Datastores & Sessions" for more information about datastores and sessions.
 *
 * @param[in] conn_ctx Connection context acquired with ::sr_connect call.
 * @param[in] user_name Effective user name used to authorize the access to
 * datastore (in addition to automatically-detected real user name).
 * @param[in] datastore Datastore on which all sysrepo functions within this
 * session will operate. Functionality of some sysrepo calls does not depend on
 * datastore. If your session will contain just calls like these, you can pass
 * any valid value (e.g. SR_RUNNING).
 * @param[in] opts Options overriding default session handling.
 * @param[out] session Session context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_session_stop).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_start_user(sr_conn_ctx_t *conn_ctx, const char *user_name, const sr_datastore_t datastore,
        const sr_conn_options_t opts, sr_session_ctx_t **session);

/**
 * @brief Stops current session and releases resources tied to the session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_stop(sr_session_ctx_t *session);

/**
 * @brief Refreshes configuration data cached within the session and starts
 * operating on fresh data loaded from the datastore.
 *
 * Call this function in case that you leave session open for longer time period
 * and you expect that the data in the datastore may have been changed since
 * last data (re)load (which occurs by ::sr_session_start, ::sr_commit and
 * ::sr_discard_changes).
 *
 * @see @ref ds_page "Datastores & Sessions" for information about session data caching.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_refresh(sr_session_ctx_t *session);

/**
 * @brief Retrieves detailed information about the error that has occurred
 * during the last operation executed within provided session.
 *
 * If multiple errors has occurred within the last operation, only the first
 * one is returned. This call is sufficient for all data retrieval and data
 * manipulation functions that operate on single-item basis. For operations
 * such as ::sr_validate or ::sr_commit where multiple errors can occur,
 * use ::sr_get_last_errors instead.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[out] error_info Detailed error information. Be aware that
 * returned pointer may change by the next API call executed within the provided
 * session,  so it's not safe to use this function by concurrent access to the
 * same session within multiple threads. Do not free or modify returned values.
 *
 * @return Error code of the last operation executed within provided session.
 */
int sr_get_last_error(sr_session_ctx_t *session, const sr_error_info_t **error_info);

/**
 * @brief Retrieves detailed information about all errors that have occurred
 * during the last operation executed within provided session.
 *
 * Use this call instead of ::sr_get_last_error by operations where multiple
 * errors can occur, such as ::sr_validate or ::sr_commit.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[out] error_info Array of detailed error information. Be aware that
 * returned pointer may change by the next API call executed within the provided
 * session,  so it's not safe to use this function by concurrent access to the
 * same session within multiple threads. Do not free or modify returned values.
 * @param[out] error_cnt Number of errors returned in the error_info array.
 *
 * @return Error code of the last operation executed within provided session.
 */
int sr_get_last_errors(sr_session_ctx_t *session, const sr_error_info_t **error_info, size_t *error_cnt);


////////////////////////////////////////////////////////////////////////////////
// Data Retrieval API (get / get-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Structure that contains information about one particular schema file installed in sysrepo.
 */
typedef struct sr_sch_revision_s {
    const char *revision;         /**< Revision of the module/submodule. */
    const char *file_path_yang;   /**< Absolute path to file where the module/submodule is stored (YANG format). */
    const char *file_path_yin;    /**< Absolute path to file where the module/submodule is stored (.yin format). */
} sr_sch_revision_t;

/**
 * @brief Structure that contains information about submodules of a module installed in sysrepo.
 */
typedef struct sr_sch_submodule_s {
    const char *submodule_name;    /**< Submodule name. */
    sr_sch_revision_t revision;    /**< Revision of the submodule. */
} sr_sch_submodule_t;

/**
 * @brief Structure that contains information about a module installed in sysrepo.
 */
typedef struct sr_schema_s {
    const char *module_name;         /**< Name of the module. */
    const char *ns;                  /**< Namespace of the module used in @ref xp_page "XPath". */
    const char *prefix;              /**< Prefix of the module. */

    sr_sch_revision_t revision;      /**< Revision the module. */

    sr_sch_submodule_t *submodules;  /**< Array of all installed submodules of the module. */
    size_t submodule_count;          /**< Number of module's submodules. */

    char **enabled_features;         /**< Array of enabled features */
    size_t enabled_feature_cnt;      /**< Number of enabled feature */
} sr_schema_t;

/**
 * @brief Format types of ::sr_get_schema result
 */
typedef enum sr_schema_format_e {
    SR_SCHEMA_YANG,                         /**< YANG format */
    SR_SCHEMA_YIN                           /**< YIN format */
}sr_schema_format_t;
/**
 * @brief Iterator used for accessing data nodes via ::sr_get_items_iter call.
 */
typedef struct sr_val_iter_s sr_val_iter_t;

/**
 * @brief Retrieves list of schemas installed in the sysrepo datastore.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[out] schemas Array of installed schemas information (allocated by
 * the function, can be completely freed with ::sr_free_schemas call).
 * @param[out] schema_cnt Number of schemas returned in the array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_list_schemas(sr_session_ctx_t *session, sr_schema_t **schemas, size_t *schema_cnt);

/**
 * @brief Retrieves the content of specified schema file. If the module
 * can not be found SR_ERR_NOT_FOUND is returned.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name Name of the requested module.
 * @param[in] revision Requested revision of the module. If NULL
 * is passed, the latest revision will be returned.
 * @param[in] submodule_name Name of the requested submodule. Pass NULL if you are
 * requesting the content of the main module.
 * @param[in] format of the returned schema
 * @param[out] schema_content Content of the specified schema file. Automatically
 * allocated by the function, should be freed by the caller.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_schema(sr_session_ctx_t *session, const char *module_name, const char *revision,
         const char *submodule_name, sr_schema_format_t format, char **schema_content);

/**
 * @brief Retrieves a single data element stored under provided XPath. If multiple
 * nodes matches the xpath SR_ERR_INVAL_ARG is returned.
 *
 * If the xpath identifies an empty leaf, a list or a container, the value
 * has no data filled in and its type is set properly (SR_LEAF_EMPTY_T / SR_LIST_T / SR_CONTAINER_T / SR_CONTAINER_PRESENCE_T).
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see Use ::sr_get_items or ::sr_get_items_iter for retrieving larger chunks
 * of data from the datastore. Since they retrieve the data from datastore in
 * larger chunks, they can work much more efficiently than multiple ::sr_get_item calls.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element to be retrieved.
 * @param[out] value Structure containing information about requested element
 * (allocated by the function, can be freed with ::sr_free_val).
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_item(sr_session_ctx_t *session, const char *xpath, sr_val_t **value);

/**
 * @brief Retrieves an array of data elements matching provided XPath
 *
 * All data elements are transferred within one message from the datastore,
 * which is much more efficient that calling multiple ::sr_get_item calls.
 *
 * If the user does not have read permission to access certain nodes, these
 * won't be part of the result. SR_ERR_NOT_FOUND will be returned if there are
 * no nodes match xpath in the data tree, or the user does not have read permission to access them.
 *
 * If the response contains too many elements time out may be exceeded, SR_ERR_TIME_OUT
 * will be returned, use ::sr_get_items_iter.
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see ::sr_get_items_iter can be used for the same purpose as ::sr_get_items
 * call if you expect that ::sr_get_items could return too large data sets.
 * Since ::sr_get_items_iter also retrieves the data from datastore in larger chunks,
 * in can still work very efficiently for large datasets.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element to be retrieved.
 * @param[out] values Array of structures containing information about requested
 * data elements (allocated by the function, can be completely freed with ::sr_free_values).
 * @param[out] value_cnt Number of returned elements in the values array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt);

/**
 * @brief Creates an iterator for retrieving of the data elements stored under provided xpath.
 *
 * Requested data elements are transferred from the datastore in larger chunks
 * of pre-defined size, which is much more efficient that calling multiple
 * ::sr_get_item calls, and may be less memory demanding than calling ::sr_get_items
 * on very large datasets.
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see ::sr_get_item_next for iterating over returned data elements.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element / subtree to be retrieved.
 * @param[out] iter Iterator context that can be used to retrieve individual data
 * elements via ::sr_get_item_next calls. Allocated by the function, should be
 * freed with ::sr_free_val_iter.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_items_iter(sr_session_ctx_t *session, const char *xpath, sr_val_iter_t **iter);

/**
 * @brief Returns the next item from the dataset of provided iterator created
 * by ::sr_get_items_iter call. If there is no item left SR_ERR_NOT_FOUND is returned.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in,out] iter Iterator acquired with ::sr_get_items_iter call.
 * @param[out] value Structure containing information about requested element
 * (allocated by the function, can be freed with ::sr_free_val).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value);


////////////////////////////////////////////////////////////////////////////////
// Data Manipulation API (edit-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Flags used to override default behavior of data manipulation calls.
 */
typedef enum sr_edit_flag_e {
    SR_EDIT_DEFAULT = 0,        /**< Default behavior - recursive and non-strict. */
    SR_EDIT_NON_RECURSIVE = 1,  /**< Non-recursive behavior:
                                     by ::sr_set_item, all preceding nodes (parents) of the identified element must exist,
                                     by ::sr_delete_item xpath must not identify an non-empty list or non-empty container. */
    SR_EDIT_STRICT = 2          /**< Strict behavior:
                                     by ::sr_set_item the identified element must not exist (similar to netconf create operation),
                                     by ::sr_delete_item the identified element must exist (similar to netconf delete operation). */
} sr_edit_flag_t;

/**
 * @brief Options overriding default behavior of data manipulation calls,
 * can be bitwise OR-ed value of any ::sr_edit_flag_t flags.
 */
typedef uint32_t sr_edit_options_t;

/**
 * @brief Options for specifying move direction of ::sr_move_item call.
 */
typedef enum sr_move_position_e {
    SR_MOVE_BEFORE = 0,    /**< Move the specified item before the selected sibling. */
    SR_MOVE_AFTER = 1,     /**< Move the specified item after the selected. */
    SR_MOVE_FIRST = 2,     /**< Move the specified item to the position of the first child. */
    SR_MOVE_LAST = 3,      /**< Move the specified item to the position of the last child. */
} sr_move_position_t;

/**
 * @brief Sets the value of the leaf, leaf-list, list or presence container.
 *
 * With default options it recursively creates all missing nodes (containers and
 * lists including their key leaves) in the xpath to the specified node (can be
 * turned off with SR_EDIT_NON_RECURSIVE option). If SR_EDIT_STRICT flag is set,
 * the node must not exist (otherwise an error is returned). Setting of a leaf-list
 * value appends the value at the end of the leaf-list. To create a list use
 * xpath with key values included and pass NULL as value argument.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element to be set.
 * @param[in] value Value to be set on specified xpath. xpath member of the
 * ::sr_val_t structure can be NULL. Value will be copied - can be allocated on stack.
 * @param[in] opts Options overriding default behavior of this call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts);

/**
 * @brief Deletes the nodes under the specified xpath.
 *
 * To delete non-empty lists or containers SR_EDIT_NON_RECURSIVE flag must not be set.
 * If SR_EDIT_STRICT flag is set the specified node must must exist in the datastore.
 * If the xpath includes the list keys, the specified list instance is deleted.
 * If the xpath to list does not include keys, all instances of the list are deleted.
 * SR_ERR_UNAUTHORIZED will be returned if the user does not have write permission to any affected node.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element to be deleted.
 * @param[in] opts Options overriding default behavior of this call.
 *
 * @return Error code (SR_ERR_OK on success).
 **/
int sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts);

/**
 * @brief Move the instance of an user-ordered list or leaf-list to the specified position.
 *
 * Item can be move to the first or last position or positioned relatively
 * to its sibling.
 * @note To determine current order, you can issue a ::sr_get_items call
 * (without specifying keys of the list in question).
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "XPath" identifier of the data element to be moved.
 * @param[in] position Requested move direction.
 * @param[in] relative_item xpath Identifier of the data element that is used
 * to determine relative position, used only if position argument is SR_MOVE_BEFORE or SR_MOVE_AFTER.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *relative_item);

/**
 * @brief Perform the validation of changes made in current session, but do not
 * commit nor discard them.
 *
 * Provides only YANG validation, commit verify subscribers won't be notified in this case.
 *
 * @see Use ::sr_get_last_errors to retrieve error information if the validation
 * returned with an error.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_validate(sr_session_ctx_t *session);

/**
 * @brief Apply changes made in current session.
 *
 * @note Note that in case that you are committing to the running datstore, you also
 * need to copy the config to startup to make changes permanent after restart.
 *
 * @see Use ::sr_get_last_errors to retrieve error information if the commit
 * operation returned with an error.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_commit(sr_session_ctx_t *session);

/**
 * @brief Discard non-committed changes made in current session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_discard_changes(sr_session_ctx_t *session);

/**
 * @brief Replaces an entire configuration datastore  with the contents of
 * another complete configuration datastore. If the module is specified, limits
 * the copy operation only to one specified module. If it's not specified,
 * the operation is performed on all modules that are currently active in the
 * source datastore.
 *
 * If the target datastore exists, it is overwritten. Otherwise, a new one is created.
 *
 * @note In the current implementation, running configuration datastore is not
 * supported as the destination datastore.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name If specified, only limits the copy operation only to
 * one specified module.
 * @param[in] src_datastore Source datastore.
 * @param[in] dst_datastore Destination datastore.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_copy_config(sr_session_ctx_t *session, const char *module_name,
        sr_datastore_t src_datastore, sr_datastore_t dst_datastore);


////////////////////////////////////////////////////////////////////////////////
// Locking API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Locks the datastore which the session is tied to. If there is
 * a module locked by the other session SR_ERR_LOCKED is returned.
 *
 * All data models within the datastore will be locked for writing until
 * ::sr_unlock_datastore is called or until the session is stopped or terminated
 * for any reason.
 *
 * The lock operation will not be allowed if the user does not have sufficient
 * permissions for writing into each of the data models in the datastore.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_lock_datastore(sr_session_ctx_t *session);

/**
 * @brief Unlocks the datastore which the session is tied to.
 *
 * All data models within the datastore will be unlocked if they were locked
 * by this session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_unlock_datastore(sr_session_ctx_t *session);

/**
 * @brief Locks specified data module within the datastore which the session
 * is tied to.
 *
 * Specified data module will be locked for writing in the datastore until
 * ::sr_unlock_module is called or until the session is stopped or terminated
 * for any reason.
 *
 * The lock operation will not be allowed if the user does not have sufficient
 * permissions for writing into the specified data module.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name Name of the module to be locked.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_lock_module(sr_session_ctx_t *session, const char *module_name);

/**
 * @brief Unlocks specified data module within the datastore which the session
 * is tied to.
 *
 * Specified data module will be unlocked if was locked in the datastore
 * by this session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name Name of the module to be unlocked.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_unlock_module(sr_session_ctx_t *session, const char *module_name);


////////////////////////////////////////////////////////////////////////////////
// Notification API - !!! EXPERIMENTAL !!!
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Sysrepo subscription context returned from sr_*_subscribe calls,
 * can be released by ::sr_unsubscribe call.
 */
typedef struct sr_subscription_ctx_s sr_subscription_ctx_t;

/**
 * @brief Callback to be called by the event of changing any running datastore
 * content within a module. Subscribe to it by ::sr_module_change_subscribe call.
 *
 * @param[in] session Automatically-created session that can be used for
 * obtaining changed data (e.g. with ::sr_get_item, ::sr_get_items or
 * ::sr_get_items_iter calls). Do not stop this session.
 * @param[in] module_name Name of the module where the change has occurred.
 * @param[in] private_ctx Private context opaque to sysrepo, as passed to
 * ::sr_module_change_subscribe call.
 */
typedef void (*sr_module_change_cb)(sr_session_ctx_t *session, const char *module_name, void *private_ctx);

/**
 * @brief Callback to be called by the event of installation / uninstallation
 * of a new module into sysrepo. Subscribe to it by ::sr_module_install_subscribe call.
 *
 * @param[in] module_name Name of the newly installed / uinstalled module.
 * @param[in] revision Revision of the newly installed module (if specified
 * within the YANG model).
 * @param[in] installed TRUE if the module has been installed, FALSE if uninstalled.
 * @param[in] private_ctx Private context opaque to sysrepo, as passed to
 * ::sr_module_install_subscribe call.
 */
typedef void (*sr_module_install_cb)(const char *module_name, const char *revision, bool installed, void *private_ctx);

/**
 * @brief Callback to be called by the event of enabling / disabling of
 * a YANG feature within a module. Subscribe to it by ::sr_feature_enable_subscribe call.
 *
 * @param[in] module_name Name of the module where the feature has been enabled / disabled.
 * @param[in] feature_name Name of the feature that has been enabled / disabled.
 * @param[in] enabled TRU if the feature has been enabled, FALSE if disabled.
 * @param[in] private_ctx Private context opaque to sysrepo, as passed to
 * ::sr_feature_enable_subscribe call.
 */
typedef void (*sr_feature_enable_cb)(const char *module_name, const char *feature_name, bool enabled, void *private_ctx);

/**
 * @brief Subscribes for notifications about the changes in any running datastore
 * content within specified module.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name Module name of the interest for change notifications.
 * @param[in] enable_running TRUE if this subscription should enable the contents
 * of the module in the running datastore (if the application subscribing to the
 * event is the "owner" of the data), FALSE otherwise (e.g. if you are just
 * interested in the changes of other application's data).
 * @param[in] callback Callback to be called when the event occurs.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[out] subscription Subscription context that can be passed to ::sr_unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, bool enable_running,
        sr_module_change_cb callback, void *private_ctx, sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribes for notifications about installation / uninstallation
 * of a new module into sysrepo.
 *
 * Mainly intended for northbound management applications that need to be
 * always aware of all active modules installed in sysrepo.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] callback Callback to be called when the event occurs.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[out] subscription Subscription context that can be passed to ::sr_unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_module_install_subscribe(sr_session_ctx_t *session, sr_module_install_cb callback, void *private_ctx,
        sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribes for notifications about enabling / disabling of
 * a YANG feature within a module.
 *
 * Mainly intended for northbound management applications that need to be
 * always aware of all active features within the modules installed in sysrepo.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] callback Callback to be called when the event occurs.
 * @param[in] private_ctx Private context passed to the callback function, opaque to sysrepo.
 * @param[out] subscription Subscription context that can be passed to ::sr_unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_feature_enable_subscribe(sr_session_ctx_t *session, sr_feature_enable_cb callback, void *private_ctx,
        sr_subscription_ctx_t **subscription);

/**
 * @brief Unsubscribes from a subscription acquired by any of sr_*_subscribe
 * calls and releases all subscription-related data.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_unsubscribe(sr_subscription_ctx_t *subscription);


////////////////////////////////////////////////////////////////////////////////
// Cleanup Routines
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Frees ::sr_val_t structure and all memory allocated within it.
 *
 * @param[in] value Value to be freed.
 */
void sr_free_val(sr_val_t *value);

/**
 * @brief Frees array of ::sr_val_t structures (and all memory allocated
 * within of each array element).
 *
 * @param[in] values Array of values to be freed.
 * @param[in] count Number of elements stored in the array.
 */
void sr_free_values(sr_val_t *values, size_t count);

/**
 * @brief Frees ::sr_val_iter_t iterator and all memory allocated within it.
 *
 * @param[in] iter Iterator to be freed.
 */
void sr_free_val_iter(sr_val_iter_t *iter);

/**
 * @brief Frees array of ::sr_schema_t structures (and all memory allocated
 * within of each array element).
 *
 * @param [in] schemas Array of schemas to be freed.
 * @param [in] count Number of elements stored in the array.
 */
void sr_free_schemas(sr_schema_t *schemas, size_t count);

/**@} cl */

#endif
