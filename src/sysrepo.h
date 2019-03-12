/**
 * @file sysrepo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief public API sysrepo header
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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
#ifndef _SYSREPO_H
#define _SYSREPO_H

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
#include <time.h>
#ifdef __APPLE__
    #include <sys/types.h>
#endif

#include <libyang/libyang.h>

#ifdef __cplusplus
extern "C" {
#endif

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
    SR_TREE_ITERATOR_T,        /**< Special type of tree node used to store all data needed for iterative tree loading. */

    SR_LIST_T,                 /**< List instance. ([RFC 6020 sec 7.8](http://tools.ietf.org/html/rfc6020#section-7.8)) */
    SR_CONTAINER_T,            /**< Non-presence container. ([RFC 6020 sec 7.5](http://tools.ietf.org/html/rfc6020#section-7.5)) */
    SR_CONTAINER_PRESENCE_T,   /**< Presence container. ([RFC 6020 sec 7.5.1](http://tools.ietf.org/html/rfc6020#section-7.5.1)) */
    SR_LEAF_EMPTY_T,           /**< A leaf that does not hold any value ([RFC 6020 sec 9.11](http://tools.ietf.org/html/rfc6020#section-9.11)) */
    SR_NOTIFICATION_T,         /**< Notification instance ([RFC 7095 sec 7.16](https://tools.ietf.org/html/rfc7950#section-7.16)) */

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
    SR_STRING_T,       /**< Human-readable string ([RFC 6020 sec 9.4](http://tools.ietf.org/html/rfc6020#section-9.4)) */
    SR_UINT8_T,        /**< 8-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT16_T,       /**< 16-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT32_T,       /**< 32-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_UINT64_T,       /**< 64-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    SR_ANYXML_T,       /**< Unknown chunk of XML ([RFC 6020 sec 7.10](https://tools.ietf.org/html/rfc6020#section-7.10)) */
    SR_ANYDATA_T,      /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
} sr_type_t;

/**
 * @brief Data of an element (if applicable), properly set according to the type.
 */
typedef union sr_data_u {
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
    char *string_val;       /**< Human-readable string ([RFC 6020 sec 9.4](http://tools.ietf.org/html/rfc6020#section-9.4)) */
    uint8_t uint8_val;      /**< 8-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    uint16_t uint16_val;    /**< 16-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    uint32_t uint32_val;    /**< 32-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    uint64_t uint64_val;    /**< 64-bit unsigned integer ([RFC 6020 sec 9.2](http://tools.ietf.org/html/rfc6020#section-9.2)) */
    char *anyxml_val;       /**< Unknown chunk of XML ([RFC 6020 sec 7.10](https://tools.ietf.org/html/rfc6020#section-7.10)) */
    char *anydata_val;      /**< Unknown set of nodes, encoded in XML ([RFC 7950 sec 7.10](https://tools.ietf.org/html/rfc7950#section-7.10)) */
} sr_data_t;

/**
 * @brief Structure that contains value of an data element stored in the sysrepo datastore.
 */
typedef struct sr_val_s {

    /**
     * XPath identifier of the data element, as defined in
     * @ref xp_page "Path Addressing" documentation
     */
    char *xpath;

    /** Type of an element. */
    sr_type_t type;

    /**
     * Flag for node with default value (applicable only for leaves).
     * It is set to TRUE only if the value was *implicitly* set by the datastore as per
     * module schema. Explicitly set/modified data element (through the sysrepo API) always
     * has this flag unset regardless of the entered value.
     */
    bool dflt;

    /** Data of an element (if applicable), properly set according to the type. */
    sr_data_t data;

} sr_val_t;

/**
 * @brief Sysrepo error codes.
 */
typedef enum sr_error_e {
    SR_ERR_OK = 0,             /**< No error. */
    SR_ERR_INVAL_ARG,          /**< Invalid argument. */
    SR_ERR_LY,                 /**< Error generated by libyang. */
    SR_ERR_SYS,                /**< System function call failed. */
    SR_ERR_NOMEM,              /**< Not enough memory. */
    SR_ERR_NOT_FOUND,          /**< Item not found. */
    SR_ERR_EXISTS,             /**< Item already exists. */
    SR_ERR_INTERNAL,           /**< Other internal error. */
    SR_ERR_INIT_FAILED,        /**< Sysrepo initialization failed. */
    SR_ERR_DISCONNECT,         /**< The peer disconnected. */
    SR_ERR_MALFORMED_MSG,      /**< Malformed message. */
    SR_ERR_UNSUPPORTED,        /**< Unsupported operation requested. */
    SR_ERR_UNKNOWN_MODEL,      /**< Request includes unknown schema */
    SR_ERR_BAD_ELEMENT,        /**< Unknown element in existing schema */
    SR_ERR_VALIDATION_FAILED,  /**< Validation of the changes failed. */
    SR_ERR_OPERATION_FAILED,   /**< An operation failed. */
    SR_ERR_UNAUTHORIZED,       /**< Operation not authorized. */
    SR_ERR_INVAL_USER,         /**< Invalid username. */
    SR_ERR_LOCKED,             /**< Requested resource is already locked. */
    SR_ERR_TIME_OUT,           /**< Time out has expired. */
    SR_ERR_CALLBACK_FAILED,    /**< User callback failure caused the operation to fail. */
} sr_error_t;

/**
 * @brief Detailed sysrepo error information.
 */
typedef struct sr_error_info_s {
    sr_error_t err_code; /**< Error code. */
    struct {
        char *message;   /**< Error message. */
        char *xpath;     /**< XPath to the node where the error has been discovered. */
    } *err;
    size_t err_count;    /**< Error message count. */
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
    SR_LL_NONE = 0,  /**< Do not print any messages. */
    SR_LL_ERR,       /**< Print only error messages. */
    SR_LL_WRN,       /**< Print error and warning messages. */
    SR_LL_INF,       /**< Besides errors and warnings, print some other informational messages. */
    SR_LL_DBG,       /**< Print all messages including some development debug messages. */
} sr_log_level_t;

/**
 * @brief Enables / disables / changes log level (verbosity) of logging to
 * standard error output.
 *
 * By default, logging to stderr is disabled. Setting log level to any value
 * other than SR_LL_NONE enables the logging to stderr. Setting log level
 * back to SR_LL_NONE disables the logging to stderr.
 *
 * @note Please note that this will overwrite your libyang logging settings.
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

const char *sr_get_repo_path(void);

////////////////////////////////////////////////////////////////////////////////
// Connection / Session Management
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Flags used to override default connection handling by ::sr_connect call.
 */
typedef enum sr_conn_flag_e {
    SR_CONN_DEFAULT = 0,          /**< No special behaviour. */
    SR_CONN_CACHE_RUNNING = 1,    /**< Always cache running datastore data which makes mainly repeated retrieval of data
                                       faster. Affects all sessions created on this connection. */
} sr_conn_flag_t;

/**
 * @brief Options overriding default connection handling by ::sr_connect call,
 * it is supposed to be bitwise OR-ed value of any ::sr_conn_flag_t flags.
 */
typedef uint32_t sr_conn_options_t;

/**
 * @brief Flags used to override default session handling (used by ::sr_session_start
 * and ::sr_session_start_user calls).
 */
typedef enum sr_session_flag_e {
    SR_SESS_DEFAULT = 0,       /**< Default (normal) session behavior. */
} sr_session_flag_t;

/**
 * @brief Options overriding default connection session handling,
 * it is supposed to be bitwise OR-ed value of any ::sr_session_flag_t flags.
 */
typedef uint32_t sr_sess_options_t;

/**
 * @brief Data stores that sysrepo supports. Both are editable via implicit candidate.
 * To make changes permanent in edited datastore ::sr_apply_changes must be issued.
 * @see @ref ds_page "Datastores & Sessions" information page.
 */
typedef enum sr_datastore_e {
    SR_DS_STARTUP = 0,     /**< Contains configuration data that will be loaded when a device starts. */
    SR_DS_RUNNING = 1,     /**< Contains current configuration data. */
    SR_DS_OPERATIONAL = 2, /**< Contains currently used configuration and state data. */
} sr_datastore_t;

/**
 * @brief Connects to the sysrepo datastore (Sysrepo Engine).
 *
 * @note If the client library loses connection to the Sysrepo Engine during
 * the lifetime of the application, all Sysrepo API calls will start returning
 * ::SR_ERR_DISCONNECT error on active sessions. In this case, the application is supposed to reconnect
 * with another ::sr_connect call and restart all lost sessions.
 *
 * @param[in] app_name Name of the application connecting to the datastore
 * (can be a static string). Used only for accounting purposes.
 * @param[in] opts Options overriding default connection handling by this call.
 * @param[out] conn_ctx Connection context that can be used for subsequent API calls
 * (automatically allocated, it is supposed to be released by the caller using ::sr_disconnect).
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
 * session will operate. Later on, datastore can be later changed using
 * ::sr_session_switch_ds call. Functionality of some sysrepo calls does not depend on
 * datastore. If your session will contain just calls like these, you can pass
 * any valid value (e.g. SR_RUNNING).
 * @param[in] opts Options overriding default session handling.
 * @param[out] session Session context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_session_stop).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_start(sr_conn_ctx_t *conn_ctx, const sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session);

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
 * @param[out] session Session context that can be used for subsequent API calls
 * (automatically allocated, it is supposed to be released by caller using ::sr_session_stop).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_start_user(sr_conn_ctx_t *conn_ctx, const char *user_name, const sr_datastore_t datastore,
        const sr_sess_options_t opts, sr_session_ctx_t **session);

/**
 * @brief Stops current session and releases resources tied to the session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_stop(sr_session_ctx_t *session);

/**
 * @brief Changes datastore to which the session is tied to. All subsequent
 * calls will be issued on the chosen datastore.
 *
 * @param [in] session
 * @param [in] ds
 * @return Error code (SR_ERR_OK on success)
 */
int sr_session_switch_ds(sr_session_ctx_t *session, sr_datastore_t ds);

sr_datastore_t sr_session_get_ds(sr_session_ctx_t *session);

/**
 * @brief Alter the session options. E.g.: set/unset SR_SESS_CONFIG_ONLY flag.
 *
 * @param [in] session
 * @param [in] opts - new value for session options
 * @return Error code (SR_ERR_OK on success)
 */
int sr_session_set_options(sr_session_ctx_t *session, const sr_sess_options_t opts);

/**
 * @brief Retrieves detailed information about the error that has occurred
 * during the last operation executed within provided session.
 *
 * If multiple errors has occurred within the last operation, only the first
 * one is returned. This call is sufficient for all data retrieval and data
 * manipulation functions that operate on single-item basis. For operations
 * such as ::sr_validate or ::sr_apply_changes where multiple errors can occur,
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
int sr_get_error(sr_session_ctx_t *session, const sr_error_info_t **error_info);

/**
 * @brief Sets detailed error information into provided session. Used to notify
 * the client library about errors that occurred in application code.
 *
 * @note Intended only for commit verifiers (notification session).
 *
 * @param[in] session Session context passed into notification callback.
 * @param[in] message Human-readable error message.
 * @param[in] xpath XPath to the node where the error has occurred. NULL value
 * is also accepted.
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_set_error(sr_session_ctx_t *session, const char *message, const char *xpath);

/**
 * @brief Returns the assigned id of the session. Can be used to pair the session with
 * netconf-config-change notification initiator.
 * @param [in] session
 * @return session id or 0 in case of error
 */
uint32_t sr_session_get_id(sr_session_ctx_t *session);

void sr_session_set_nc_id(sr_session_ctx_t *session, uint32_t nc_sid);

uint32_t sr_session_get_nc_id(sr_session_ctx_t *session);

void sr_session_set_user(sr_session_ctx_t *session, const char *user);

const char *sr_session_get_user(sr_session_ctx_t *session);

sr_conn_ctx_t *sr_session_get_connection(sr_session_ctx_t *session);

////////////////////////////////////////////////////////////////////////////////
// Data Retrieval API (get / get-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Retrieves a single data element stored under provided XPath. If multiple
 * nodes matches the xpath SR_ERR_INVAL_ARG is returned.
 *
 * If the xpath identifies an empty leaf, a list or a container, the value
 * has no data filled in and its type is set properly (SR_LEAF_EMPTY_T / SR_LIST_T / SR_CONTAINER_T / SR_CONTAINER_PRESENCE_T).
 *
 * @see @ref xp_page "Path Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see Use ::sr_get_items or ::sr_get_items_iter for retrieving larger chunks
 * of data from the datastore. Since they retrieve the data from datastore in
 * larger chunks, they can work much more efficiently than multiple ::sr_get_item calls.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the data element to be retrieved.
 * @param[out] value Structure containing information about requested element
 * (allocated by the function, it is supposed to be freed by the caller using ::sr_free_val).
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
 * no nodes matching xpath in the data tree, or the user does not have read permission to access them.
 *
 * If the response contains too many elements time out may be exceeded, SR_ERR_TIME_OUT
 * will be returned, use ::sr_get_items_iter.
 *
 * @see @ref xp_page "Path Addressing" documentation
 * for Path syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see ::sr_get_items_iter can be used for the same purpose as ::sr_get_items
 * call if you expect that ::sr_get_items could return too large data sets.
 * Since ::sr_get_items_iter also retrieves the data from datastore in larger chunks,
 * in can still work very efficiently for large datasets.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the data element to be retrieved.
 * @param[out] values Array of structures containing information about requested data elements
 * (allocated by the function, it is supposed to be freed by the caller using ::sr_free_values).
 * @param[out] value_cnt Number of returned elements in the values array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_items(sr_session_ctx_t *session, const char *xpath, sr_val_t **values, size_t *value_cnt);

/**
 * @brief Retrieves a single subtree whose root node is stored under the provided XPath.
 * If multiple nodes matches the xpath SR_ERR_INVAL_ARG is returned.
 *
 * The functions returns values and all associated information stored under the root node and
 * all its descendants. While the same data can be obtained using ::sr_get_items in combination
 * with the expressive power of XPath addressing, the recursive nature of the output data type
 * also preserves the hierarchical relationships between data elements.
 *
 * Values of internal nodes of the subtree have no data filled in and their type is set properly
 * (SR_LIST_T / SR_CONTAINER_T / SR_CONTAINER_PRESENCE_T), whereas leaf nodes are carrying actual
 * data (apart from SR_LEAF_EMPTY_T).
 *
 * @see @ref xp_page "Path Addressing" documentation
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier referencing the root node of the subtree to be retrieved.
 * @param[in] opts Options overriding default behavior of this operation.
 * @param[out] subtree Nested structure storing all data of the requested subtree
 * (allocated by the function, it is supposed to be freed by the caller using ::sr_free_tree).
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_subtree(sr_session_ctx_t *session, const char *xpath, struct lyd_node **subtree);

/**
 * @brief Retrieves an array of subtrees whose root nodes match the provided XPath.
 *
 * If the user does not have read permission to access certain nodes, these together with
 * their descendants won't be part of the result. SR_ERR_NOT_FOUND will be returned if there are
 * no nodes matching xpath in the data tree, or the user does not have read permission to access them.
 *
 * Subtrees that match the provided XPath are not merged even if they overlap. This significantly
 * simplifies the implementation and decreases the cost of this operation. The downside is that
 * the user must choose the XPath carefully. If the subtree selection process results in too many
 * node overlaps, the cost of the operation may easily outshine the benefits. As an example,
 * a common XPath expression "//." is normally used to select all nodes in a data tree, but for this
 * operation it would result in an excessive duplication of transfered data elements.
 * Since you get all the descendants of each matched node implicitly, you probably should not need
 * to use XPath wildcards deeper than on the top-level.
 * (i.e. "/." is preferred alternative to "//." for get-subtrees operation).
 *
 * If the response contains too many elements time out may be exceeded, SR_ERR_TIME_OUT
 * will be returned.
 *
 * @see @ref xp_page "Path Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier referencing root nodes of subtrees to be retrieved.
 * @param[in] opts Options overriding default behavior of this operation.
 * @param[out] subtrees Array of nested structures storing all data of the requested subtrees
 * (allocated by the function, it is supposed to be freed by the caller using ::sr_free_trees).
 * @param[out] subtree_cnt Number of returned trees in the subtrees array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_subtrees(sr_session_ctx_t *session, const char *xpath, struct ly_set **subtrees);


////////////////////////////////////////////////////////////////////////////////
// Data Manipulation API (edit-config functionality)
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Flags used to override default behavior of data manipulation calls.
 */
typedef enum sr_edit_flag_e {
    SR_EDIT_DEFAULT = 0,        /**< Default behavior - non-strict. */
    SR_EDIT_NON_RECURSIVE = 1,  /**< Non-recursive behavior:
                                     by ::sr_set_item, all preceding nodes (parents) of the identified element must exist. */
    SR_EDIT_STRICT = 2          /**< Strict behavior:
                                     by ::sr_set_item the identified element must not exist (similar to netconf create operation),
                                     by ::sr_delete_item the identified element must exist (similar to netconf delete operation). */
} sr_edit_flag_t;

/**
 * @brief Options overriding default behavior of data manipulation calls,
 * it is supposed to be bitwise OR-ed value of any ::sr_edit_flag_t flags.
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
 * the node must not exist (otherwise an error is returned).
 *
 * To create a list use xpath with key values included and pass NULL as value argument.
 *
 * Setting of a leaf-list value appends the value at the end of the leaf-list.
 * A value of leaf-list can be specified either by predicate in xpath or by value argument.
 * If both are present, value argument is ignored and xpath predicate is used.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the data element to be set.
 * @param[in] value Value to be set on specified xpath. xpath member of the
 * ::sr_val_t structure can be NULL. Value will be copied - can be allocated on stack.
 * @param[in] opts Options overriding default behavior of this call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_set_item(sr_session_ctx_t *session, const char *xpath, const sr_val_t *value, const sr_edit_options_t opts);

/**
 * @brief Functions is similar to ::sr_set_item with the difference that the value to be set
 * is provided as string.
 * @param [in] session Session context acquired with ::sr_session_start call.
 * @param [in] xpath @ref xp_page "Data Path" identifier of the data element to be set.
 * @param [in] value string representation of the value to be set
 * @param [in] opts same as for ::sr_set_item
 * @return Error code (SR_ERR_OK on success).
 */
int sr_set_item_str(sr_session_ctx_t *session, const char *xpath, const char *value, const sr_edit_options_t opts);

/**
 * @brief Deletes the nodes under the specified xpath.
 *
 * If SR_EDIT_STRICT flag is set the specified node must must exist in the datastore.
 * If the xpath includes the list keys, the specified list instance is deleted.
 * If the xpath to list does not include keys, all instances of the list are deleted.
 * SR_ERR_UNAUTHORIZED will be returned if the user does not have write permission to any affected node.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the data element to be deleted.
 * @param[in] opts Options overriding default behavior of this call.
 *
 * @return Error code (SR_ERR_OK on success).
 **/
int sr_delete_item(sr_session_ctx_t *session, const char *xpath, const sr_edit_options_t opts);

/**
 * @brief Move the instance of an user-ordered list or leaf-list to the specified position.
 *
 * Item can be move to the first or last position or positioned relatively to its sibling.
 * @note To determine current order, you can issue a ::sr_get_items call
 * (without specifying keys of the list in question).
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the data element to be moved.
 * @param[in] position Requested move direction.
 * @param[in] relative_item xpath Identifier of the data element that is used
 * to determine relative position, used only if position argument is SR_MOVE_BEFORE or SR_MOVE_AFTER.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_move_item(sr_session_ctx_t *session, const char *xpath, const sr_move_position_t position, const char *list_keys,
        const char *leaflist_value);

int sr_edit_batch(sr_session_ctx_t *session, const struct lyd_node *edit, const char *default_operation);

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
int sr_apply_changes(sr_session_ctx_t *session);

/**
 * @brief Discard non-committed changes made in current session.
 *
 * @note Since the function effectively clears all the cached data within the session,
 * the next operation will operate on fresh data loaded from the datastore
 * (i.e. no need to call ::sr_session_refresh afterwards).
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
 * @note ::sr_session_refresh is needed to see the result of a copy-config operation
 * in a session apart from the case when SR_DS_CANDIDATE is the destination datastore.
 * Since the candidate is not shared among sessions, data trees are copied only to the
 * canidate in the session issuing the copy-config operation.
 *
 * @note Operation may fail, if it tries to copy a not enabled configuration to the
 * running datastore.
 *
 * @note \p session \p dst_datastore uncommitted changes will get discarded.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name If specified, only limits the copy operation only to
 * one specified module.
 * @param[in] src_datastore Source datastore.
 * @param[in] dst_datastore Destination datastore.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_copy_config(sr_session_ctx_t *session, const char *module_name, sr_datastore_t src_datastore,
        sr_datastore_t dst_datastore);

int sr_replace_config(sr_session_ctx_t *session, const char *module_name, struct lyd_node *src_config,
        sr_datastore_t dst_datastore);

////////////////////////////////////////////////////////////////////////////////
// Locking API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Locks specified data module within the datastore which the session
 * is tied to. Operation fails if the data tree has been modified.
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
int sr_lock(sr_session_ctx_t *session, const char *module_name);

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
int sr_unlock(sr_session_ctx_t *session, const char *module_name);


////////////////////////////////////////////////////////////////////////////////
// Change Notifications API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Flags used to override default handling of subscriptions.
 */
typedef enum sr_subscr_flag_e {
    /**
     * @brief Default behavior of the subscription. In case of ::sr_module_change_subscribe call it means that:
     *
     * - the subscriber is the "owner" of the subscribed data tree and and the data tree will be enabled in the running
     *   datastore while this subscription is alive (if not already, can be changed using ::SR_SUBSCR_PASSIVE flag),
     * - configuration data of the subscribed module or subtree is copied from startup to running datastore
     *   (only if the module was not enabled before),
     * - the callback will be called twice, once with ::SR_EV_CHANGE event and once with ::SR_EV_DONE / ::SR_EV_ABORT
     *   event passed in (can be changed with ::SR_SUBSCR_DONE_ONLY flag).
     */
    SR_SUBSCR_DEFAULT = 0,

    /**
     * @brief This option enables the application to re-use an already existing subscription context previously returned
     * from any sr_*_subscribe call instead of requesting the creation of a new one. In that case a single
     * ::sr_unsubscribe call unsubscribes from all subscriptions filed within the context.
     */
    SR_SUBSCR_CTX_REUSE = 1,

    /**
     * @brief The subscriber is not the "owner" of the subscribed data tree, just a passive watcher for changes.
     * When this option is passed in to ::sr_module_change_subscribe or ::sr_subtree_change_subscribe,
     * the subscription will have no effect on the presence of the subtree in the running datastore.
     */
    SR_SUBSCR_PASSIVE = 2,

    /**
     * @brief The subscriber does not support verification of the changes and wants to be notified only after
     * the changes has been applied in the datastore, without the possibility to deny them
     * (it will receive only ::SR_EV_DONE events).
     */
    SR_SUBSCR_DONE_ONLY = 4,

    /**
     * @brief The subscriber wants to be notified about current configuration at the moment of subscribing.
     */
    SR_SUBSCR_ENABLED = 8,

    /**
     * @brief The subscriber will be called before any other subscribers for the particular module
     * and is allowed to modify the new module data.
     */
    SR_SUBSCR_UPDATE = 16,

} sr_subscr_flag_t;

/**
 * @brief Type of the notification event that has occurred (passed to notification callbacks).
 *
 * @note Each change is normally notified twice: first as ::SR_EV_VERIFY event and then as ::SR_EV_APPLY or ::SR_EV_ABORT
 * event. If the subscriber does not support verification, it can subscribe only to ::SR_EV_APPLY event by providing
 * ::SR_SUBSCR_APPLY_ONLY subscription flag.
 */
typedef enum sr_notif_event_e {
    SR_EV_UPDATE,  /**< Occurs before any other events and the subscriber can update the apply-changes diff. */
    SR_EV_CHANGE,  /**< Occurs just before the changes are committed to the datastore,
                        the subscriber is supposed to verify that the changes are valid and can be applied
                        and prepare all resources required for the changes. The subscriber can still deny the changes
                        in this phase by returning an error from the callback. */
    SR_EV_DONE,    /**< Occurs just after the changes have been successfully committed to the datastore,
                        the subscriber is supposed to apply the changes now, but it cannot deny the changes in this
                        phase anymore (any returned errors are just logged and ignored). */
    SR_EV_ABORT,   /**< Occurs in case that the commit transaction has failed (possibly because one of the verifiers
                        has denied the change / returned an error). The subscriber is supposed to return the managed
                        application to the state before the commit. Any returned errors are just logged and ignored. */
} sr_notif_event_t;

/**
 * @brief Type of the operation made on an item, used by changeset retrieval in ::sr_get_change_next.
 */
typedef enum sr_change_oper_e {
    SR_OP_CREATED,   /**< The item has been created by the change. */
    SR_OP_MODIFIED,  /**< The value of the item has been modified by the change. */
    SR_OP_DELETED,   /**< The item has been deleted by the change. */
    SR_OP_MOVED,     /**< The item has been moved in the subtree by the change (applicable for leaf-lists and user-ordered lists). */
} sr_change_oper_t;

/**
 * @brief Sysrepo subscription context returned from sr_*_subscribe calls,
 * it is supposed to be released by the caller using ::sr_unsubscribe call.
 */
typedef struct sr_subscription_ctx_s sr_subscription_ctx_t;

/**
 * @brief Iterator used for retrieval of a changeset using ::sr_get_changes_iter call.
 */
typedef struct sr_change_iter_s sr_change_iter_t;

/**
 * @brief Options overriding default behavior of subscriptions,
 * it is supposed to be a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 */
typedef uint32_t sr_subscr_options_t;

/**
 * @brief Callback to be called by the event of changing any running datastore
 * content within the specified module. Subscribe to it by ::sr_module_change_subscribe call.
 *
 * @param[in] session Automatically-created session that can be used for obtaining changed data
 * (e.g. by ::sr_get_changes_iter call ot ::sr_get_item -like calls). Do not stop this session.
 * @param[in] module_name Name of the module where the change has occurred.
 * @param[in] xpath XPath used when subscribing, NULL if the whole module was subscribed to.
 * @param[in] event Type of the notification event that has occurred.
 * @param[in] private_data Private context opaque to sysrepo, as passed to
 * ::sr_module_change_subscribe call.
 */
typedef int (*sr_module_change_cb)(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_notif_event_t event, void *private_data);

/**
 * @brief Subscribes for notifications about the changes made within specified
 * module in running datastore.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] module_name Name of the module of interest for change notifications.
 * @param[in] xpath Further filter the changes that will be handled by this subscription. Set NULL for the whole module.
 * @param[in] callback Callback to be called when the change in the datastore occurs.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] priority Specifies the order in which the callbacks will be called (callbacks with higher
 * priority will be called sooner, callbacks with the priority of 0 will be called at the end).
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_module_change_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_module_change_cb callback, void *private_data, uint32_t priority, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription);

/**
 * @brief Unsubscribes from a subscription acquired by any of sr_*_subscribe
 * calls and releases all subscription-related data.
 *
 * @note In case that the same subscription context was used to subscribe for
 * multiple subscriptions, unsubscribes from all of them.
 *
 * @param[in] subscription Subscription context acquired by any of sr_*_subscribe calls.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_unsubscribe(sr_subscription_ctx_t *subscription);

/**
 * @brief Creates an iterator for retrieving of the changeset (list of newly
 * added / removed / modified nodes) in notification callbacks.
 *
 * @see ::sr_get_change_next for iterating over the changeset using this iterator.
 *
 * @param[in] session Session context as passed to notication the callbacks (e.g.
 * ::sr_module_change_cb or ::sr_subtree_change_cb). Will not work with any other sessions.
 * @param[in] xpath @ref xp_page "Data Path" identifier of the subtree from which the changeset
 * should be obtained. Only XPaths that would be accepted by ::sr_subtree_change_subscribe are allowed.
 * @param[out] iter Iterator context that can be used to retrieve individual changes using
 * ::sr_get_change_next calls. Allocated by the function, should be freed with ::sr_free_change_iter.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_changes_iter(sr_session_ctx_t *session, const char *xpath, sr_change_iter_t **iter);

/**
 * @brief Returns the next change from the changeset of provided iterator created
 * by ::sr_get_changes_iter call. If there is no item left, SR_ERR_NOT_FOUND is returned.
 *
 * @note If the operation is ::SR_OP_MOVED the meaning of new_value and old value argument is
 * as follows - the value pointed by new_value was moved after the old_value. If the
 * old value is NULL it was moved to the first position.
 *
 * @param[in] session Session context as passed to notication the callbacks (e.g.
 * ::sr_module_change_cb or ::sr_subtree_change_cb). Will not work with any other sessions.
 * @param[in,out] iter Iterator acquired with ::sr_get_changes_iter call.
 * @param[out] operation Type of the operation made on the returned item.
 * @param[out] old_value Old value of the item (the value before the change).
 * NULL in case that the item has been just created (operation == SR_OP_CREATED).
 * @param[out] new_value New (modified) value of the the item. NULL in case that
 * the item has been just deleted (operation == SR_OP_DELETED).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_change_next(sr_session_ctx_t *session, sr_change_iter_t *iter, sr_change_oper_t *operation,
        sr_val_t **old_value, sr_val_t **new_value);


////////////////////////////////////////////////////////////////////////////////
// RPC (Remote Procedure Calls) and Action API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Callback to be called by the delivery of RPC specified by xpath.
 * Subscribe to it by ::sr_rpc_subscribe call.
 *
 * @param[in] xpath @ref xp_page "Data Path" identifying the RPC.
 * @param[in] input Array of input parameters.
 * @param[in] input_cnt Number of input parameters.
 * @param[out] output Array of output parameters. Should be allocated on heap,
 * will be freed by sysrepo after sending of the RPC response.
 * @param[out] output_cnt Number of output parameters.
 * @param[in] private_data Private context opaque to sysrepo, as passed to ::sr_rpc_subscribe call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
typedef int (*sr_rpc_cb)(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt, void *private_data);

/**
 * @brief Callback to be called by the delivery of RPC specified by xpath.
 * This RPC callback variant operates with sysrepo trees rather than with sysrepo values,
 * use it with ::sr_rpc_subscribe_tree and ::sr_rpc_send_tree.
 *
 * @param[in] xpath @ref xp_page "Data Path" identifying the RPC.
 * @param[in] input Array of input parameters (represented as trees).
 * @param[out] output Array of output parameters (represented as trees). Should be allocated on heap,
 * will be freed by sysrepo after sending of the RPC response.
 * @param[in] private_data Private context opaque to sysrepo, as passed to ::sr_rpc_subscribe_tree call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
typedef int (*sr_rpc_tree_cb)(sr_session_ctx_t *session, const char *xpath, const struct lyd_node *input,
        struct lyd_node *output, void *private_data);

/**
 * @brief Subscribes for delivery of RPC specified by xpath.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Schema Path" identifying the RPC.
 * @param[in] callback Callback to be called when the RPC is called.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_rpc_subscribe(sr_session_ctx_t *session, const char *xpath, sr_rpc_cb callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribes for delivery of RPC specified by xpath. Unlike ::sr_rpc_subscribe, this
 * function expects callback of type ::sr_rpc_tree_cb, therefore use this version if you prefer
 * to manipulate with RPC input and output data organized in a list of trees rather than as a flat
 * enumeration of all values.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Schema Path" identifying the RPC.
 * @param[in] callback Callback to be called when the RPC is called.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_rpc_subscribe_tree(sr_session_ctx_t *session, const char *xpath, sr_rpc_tree_cb callback,
        void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Sends a RPC specified by xpath and waits for the result.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifying the RPC.
 * @param[in] input Array of input parameters (array of all nodes that hold some
 * data in RPC input subtree - same as ::sr_get_items would return).
 * @param[in] input_cnt Number of input parameters.
 * @param[out] output Array of output parameters (all nodes that hold some data
 * in RPC output subtree). Will be allocated by sysrepo and should be freed by
 * caller using ::sr_free_values.
 * @param[out] output_cnt Number of output parameters.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_rpc_send(sr_session_ctx_t *session, const char *xpath, const sr_val_t *input, const size_t input_cnt,
        sr_val_t **output, size_t *output_cnt);

/**
 * @brief Sends a RPC specified by xpath and waits for the result. Input and output data
 * are represented as arrays of subtrees reflecting the scheme of RPC arguments.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] input Array of input parameters (organized in trees).
 * @param[out] output Array of output parameters (organized in trees).
 * Will be allocated by sysrepo and should be freed by caller using ::sr_free_trees.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_rpc_send_tree(sr_session_ctx_t *session, struct lyd_node *input, struct lyd_node **output);


////////////////////////////////////////////////////////////////////////////////
// Event Notifications API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Type of the notification passed to the ::sr_event_notif_cb and ::sr_event_notif_tree_cb callbacks.
 */
typedef enum sr_ev_notif_type_e {
    SR_EV_NOTIF_REALTIME,         /**< Real-time notification. The only possible type if you don't use ::sr_event_notif_replay. */
    SR_EV_NOTIF_REPLAY,           /**< Replayed notification. */
    SR_EV_NOTIF_REPLAY_COMPLETE,  /**< Not a real notification, just a signal that the notification replay has completed
                                       (all the stored notifications from the given time interval have been delivered). */
    SR_EV_NOTIF_STOP,             /**< Not a real notification, just a signal that replay stop time has been reached
                                       (delivered only if stop_time was specified to ::sr_event_notif_replay). */
} sr_ev_notif_type_t;

/**
 * @brief Flags used to override default notification handling i the datastore.
 */
typedef enum sr_ev_notif_flag_e {
    SR_NOTIF_DEFAULT = 0,      /**< Notification will be handled normally. */
} sr_ev_notif_flag_t;

/**
 * @brief Callback to be called by the delivery of event notification specified by xpath.
 * Subscribe to it by ::sr_event_notif_subscribe call.
 *
 * @param[in] notif_type Type of the notification.
 * @param[in] xpath @ref xp_page "Data Path" identifying the event notification.
 * @param[in] values Array of all nodes that hold some data in event notification subtree.
 * @param[in] values_cnt Number of items inside the values array.
 * @param[in] timestamp Time when the notification was generated
 * @param[in] private_data Private context opaque to sysrepo,
 * as passed to ::sr_event_notif_subscribe call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
typedef void (*sr_event_notif_cb)(const sr_ev_notif_type_t notif_type, const char *xpath,
        const sr_val_t *values, const size_t values_cnt, time_t timestamp, void *private_data);

/**
 * @brief Callback to be called by the delivery of event notification specified by xpath.
 * This callback variant operates with sysrepo trees rather than with sysrepo values,
 * use it with ::sr_event_notif_subscribe_tree and ::sr_event_notif_send_tree.
 *
 * @param[in] notif_type Type of the notification.
 * @param[in] xpath @ref xp_page "Data Path" identifying the event notification.
 * @param[in] trees Array of subtrees carrying event notification data.
 * @param[in] tree_cnt Number of subtrees with data.
 * @param[in] timestamp Time when the notification was generated
 * @param[in] private_data Private context opaque to sysrepo, as passed to ::sr_event_notif_subscribe_tree call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
typedef void (*sr_event_notif_tree_cb)(const sr_ev_notif_type_t notif_type, const struct lyd_node *notif,
        time_t timestamp, void *private_data);

/**
 * @brief Subscribes for delivery of an event notification specified by xpath.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Schema Path" identifying one event notification or special
 * path in the form of a module name in which the whole module is subscribed to.
 * @param[in] callback Callback to be called when the event notification is send.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_event_notif_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath, time_t start_time,
        time_t stop_time, sr_event_notif_cb callback, void *private_data, sr_subscr_options_t opts,
        sr_subscription_ctx_t **subscription);

/**
 * @brief Subscribes for delivery of event notification specified by xpath.
 * Unlike ::sr_event_notif_subscribe, this function expects callback of type ::sr_event_notif_tree_cb,
 * therefore use this version if you prefer to manipulate with event notification data organized
 * in a list of trees rather than as a flat enumeration of all values.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Schema Path" identifying one event notification or special
 * path in the form of a module name in which the whole module is subscribed to.
 * @param[in] callback Callback to be called when the event notification is called.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 * @note An existing context may be passed in case that SR_SUBSCR_CTX_REUSE option is specified.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_event_notif_subscribe_tree(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        time_t start_time, time_t stop_time, sr_event_notif_tree_cb callback, void *private_data,
        sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);

/**
 * @brief Sends an event notification specified by xpath and waits for the result.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifying the event notification.
 * @param[in] values Array of all nodes that hold some data in event notification subtree
 * (same as ::sr_get_items would return).
 * @param[in] values_cnt Number of items inside the values array.
 * @param[in] opts Options overriding default handling of the notification, it is supposed to be
 * a bitwise OR-ed value of any ::sr_ev_notif_flag_t flags.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_event_notif_send(sr_session_ctx_t *session, const char *xpath, const sr_val_t *values,
        const size_t values_cnt, sr_ev_notif_flag_t opts);

/**
 * @brief Sends an event notification specified by xpath and waits for the result.
 * The notification data are represented as arrays of subtrees reflecting the scheme
 * of the event notification.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifying the RPC.
 * @param[in] trees Array of subtrees carrying event notification data.
 * @param[in] tree_cnt Number of subtrees with data.
 * @param[in] opts Options overriding default handling of the notification, it is supposed to be
 * a bitwise OR-ed value of any ::sr_ev_notif_flag_t flags.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_event_notif_send_tree(sr_session_ctx_t *session, struct lyd_node *notif, sr_ev_notif_flag_t opts);


////////////////////////////////////////////////////////////////////////////////
// Operational Data API
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Callback to be called when operational data at the selected level is requested.
 * Subscribe to it by ::sr_dp_get_items_subscribe call.
 *
 * Callback handler is supposed to provide data of all nodes at the level selected by the xpath argument:
 *
 * - If the xpath identifies a container, the provider is supposed to return all leaves and leaf-lists values within it.
 * Nested lists and containers should not be provided - sysrepo will ask for them in subsequent calls.
 * - If the xpath identifies a list, the provider is supposed to return all leaves (except for keys!) and
 * leaf-lists values within all instances of the list. Nested lists and containers should not be provided - sysrepo
 * will ask for them in subsequent calls.
 * - If the xpath identifies a leaf-list, the provider is supposed to return all leaf-list values.
 * - If the xpath identifies a leaf, the provider is supposed to return just the leaf in question.
 *
 * The xpath argument passed to callback can be only the xpath that was used for the subscription, or xpath of
 * any nested lists or containers.
 *
 * @param[in] xpath @ref xp_page "Data Path" identifying the level under which the nodes are requested.
 * @param[out] values Array of values at the selected level (allocated by the provider).
 * @param[out] values_cnt Number of values returned.
 * @param[in] private_data Private context opaque to sysrepo, as passed to ::sr_dp_get_items_subscribe call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
typedef int (*sr_dp_get_items_cb)(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        struct lyd_node **parent, void *private_data);

/**
 * @brief Registers for providing of operational data under given xpath.
 *
 * @note The XPath must be generic - must not include any list key values.
 * @note This API works only for operational data (subtrees marked in YANG as "config false").
 * Subscribing as a data provider for configuration data does not have any effect.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] xpath @ref xp_page "Data Path" identifying the subtree under which the provider is able to provide
 * operational data.
 * @param[in] callback Callback to be called when the operational data nder given xpat is needed.
 * @param[in] private_data Private context passed to the callback function, opaque to sysrepo.
 * @param[in] opts Options overriding default behavior of the subscription, it is supposed to be
 * a bitwise OR-ed value of any ::sr_subscr_flag_t flags.
 * @param[in,out] subscription Subscription context that is supposed to be released by ::sr_unsubscribe.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_dp_get_items_subscribe(sr_session_ctx_t *session, const char *module_name, const char *xpath,
        sr_dp_get_items_cb callback, void *private_data, sr_subscr_options_t opts, sr_subscription_ctx_t **subscription);


////////////////////////////////////////////////////////////////////////////////
// Schema Manipulation API
////////////////////////////////////////////////////////////////////////////////

const struct ly_ctx *sr_get_context(sr_conn_ctx_t *conn);

int sr_install_module(sr_conn_ctx_t *conn, const char *module_path, const char *search_dir, const char **features,
        int feat_count);

int sr_remove_module(sr_conn_ctx_t *conn, const char *module_name);

int sr_update_module(sr_conn_ctx_t *conn, const char *module_path, const char *search_dir);

int sr_cancel_update_module(sr_conn_ctx_t *conn, const char *module_name);

int sr_set_module_replay_support(sr_conn_ctx_t *conn, const char *module_name, int replay_support);

int sr_set_module_access(sr_conn_ctx_t *conn, const char *module_name, const char *owner, const char *group, mode_t perm);

int sr_get_module_access(sr_conn_ctx_t *conn, const char *module_name, char **owner, char **group, mode_t *perm);

int sr_enable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name);

int sr_disable_module_feature(sr_conn_ctx_t *conn, const char *module_name, const char *feature_name);

int sr_get_module_info(sr_conn_ctx_t *conn, struct lyd_node **sysrepo_data);


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
 * @brief Frees ::sr_change_iter_t iterator and all memory allocated within it.
 *
 * @param[in] iter Iterator to be freed.
 */
void sr_free_change_iter(sr_change_iter_t *iter);

/**@} cl */

#ifdef __cplusplus
}
#endif

#endif /* _SYSREPO_H */
