/**
 * @file sysrepo.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo client library API.
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
// Typedefs and Common API
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
    SR_LEAF_EMPTY_T,           /**< A leaf that does not have any value ([RFC 6020 sec 9.11](http://tools.ietf.org/html/rfc6020#section-9.11)) */
    SR_UNION_T,                /**< Choice of member types ([RFC 6020 sec 9.12](http://tools.ietf.org/html/rfc6020#section-9.12)) */

    /* types containing some data */
    SR_BINARY_T,       /**< Any binary data ([RFC 6020 sec 9.8](http://tools.ietf.org/html/rfc6020#section-9.8)) */
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
     * XPath instance-identifier of an item in JSON format, as defined at
     * https://tools.ietf.org/html/draft-ietf-netmod-yang-json-02#section-6.11
     */
    char *xpath;

    /** Type of an element. */
    sr_type_t type;

    /** Data of an element (if applicable), properly set according to the type. */
    union {
        char *binary_val;       /**< Any binary data ([RFC 6020 sec 9.8](http://tools.ietf.org/html/rfc6020#section-9.8)) */
        char *bits_val;         /**< A set of bits or flags ([RFC 6020 sec 9.7](http://tools.ietf.org/html/rfc6020#section-9.7)) */
        bool bool_val;          /**< A boolean value ([RFC 6020 sec 9.5](http://tools.ietf.org/html/rfc6020#section-9.5)) */
        int64_t decimal64_val;  /**< 64-bit signed decimal number ([RFC 6020 sec 9.3](http://tools.ietf.org/html/rfc6020#section-9.3)) */
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

    /** Length of the data, applicable for those data types where the length may vary. */
    uint32_t length;
} sr_val_t;

/**
 * @brief Structure that contains information about a schema supported by sysrepo.
 */
typedef struct sr_schema_s {
    char *module_name;      /**< Name of the module. */
    char *ns;               /**< Namespace of the module used in @ref xp_page "XPath". */
    char *prefix;           /**< Prefix of the module. */
    char *revision;         /**< Latest revision date of the module. */
    char *file_path;        /**< Absolute path to file where the schema is stored. */
} sr_schema_t;

/**
 * @brief Iterator used for accessing data nodes via ::sr_get_items_iter call.
 */
typedef struct sr_val_iter_s sr_val_iter_t;

/**
 * @brief Sysrepo error codes.
 */
typedef enum sr_error_e {
    SR_ERR_OK = 0,         /**< No error. */
    SR_ERR_INVAL_ARG,      /**< Invalid argument. */
    SR_ERR_NOMEM,          /**< Not enough memory. */
    SR_ERR_NOT_FOUND,      /**< Item not found. */
    SR_ERR_INTERNAL,       /**< Other internal error. */
    SR_ERR_INIT_FAILED,    /**< Sysrepo infra initialization failed. */
    SR_ERR_IO,             /**< Input/Output error. */
    SR_ERR_DISCONNECT,     /**< The peer disconnected. */
    SR_ERR_MALFORMED_MSG,  /**< Malformed message. */
    SR_ERR_UNSUPPORTED,    /**< Unsupported operation requested. */
    SR_ERR_UNKNOWN_MODEL,  /**< Request includes unknown schema */
} sr_error_t;

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
 * @brief Returns the error message corresponding to the error code.
 *
 * @param[in] err_code Error code.
 *
 * @return Error message (statically allocated, do not free).
 */
const char *sr_strerror(int err_code);

/**
 * @brief Sets logging level of stderr logs and syslog logs.
 *
 * When connected to sysrepo daemon, this affects only logging of Client Library.
 * In library mode, this settings affect also local Sysrepo Engine logging.
 *
 * @param[in] ll_stderr Log level for stderr logs.
 * @param[in] ll_syslog Log level for syslog logs.
 */
void sr_logger_set_level(sr_log_level_t ll_stderr, sr_log_level_t ll_syslog);


////////////////////////////////////////////////////////////////////////////////
// Connection / Session Management
////////////////////////////////////////////////////////////////////////////////

/**
 * @brief Data stores that sysrepo supports.
 */
typedef enum sr_datastore_e {
    SR_DS_RUNNING = 0,    /**< Currently running configuration.
                               @note Direct writes to running are not allowed, changes need to be made via candidate. */
    SR_DS_CANDIDATE = 1,  /**< Candidate datastore - accepts configuration changes.
                               @note Candidate is isolated for each session (not committed changes are not visible in other sessions). */
    SR_DS_STARTUP = 2     /**< Configuration loaded upon application startup.
                               @note Direct writes to startup are not allowed, changes need to be made via running. */
} sr_datastore_t;

/**
 * @brief Connects to the sysrepo datastore (Sysrepo Engine).
 *
 * @param[in] app_name Name of the application connecting to the datastore
 * (can be static string). Used only for accounting purposes.
 * @param[in] allow_library_mode Flag which indicates if the application wants
 * to allow local (library) mode in case that sysrepo daemon is not running.
 * If set to FALSE and the library cannot connect to the deamon, an error will
 * be returned. Otherwise library will initialize its own Sysrepo Engine if the
 * connection to daemon is not possible (but only once per application process).
 * @param[out] conn_ctx Connection context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_disconnect).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_connect(const char *app_name, const bool allow_library_mode, sr_conn_ctx_t **conn_ctx);

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
 * @param[in] conn_ctx Connection context acquired with ::sr_connect call.
 * @param[in] user_name Effective user name used to authorize the access to
 * datastore (in addition to automatically-detected real user name). If not
 * provided, only automatically-detected real user name will be used for authorization.
 * @param[in] datastore Datastore on which all sysrepo functions within this
 * session will operate. Functionality of some sysrepo calls does not depend on
 * datastore. If your session will contain just calls like these, you can pass
 * any valid value (e.g. SR_RUNNING).
 * @param[out] session Session context that can be used for subsequent API
 * calls (automatically allocated, can be released by calling ::sr_session_stop).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_start(sr_conn_ctx_t *conn_ctx, const char *user_name, sr_datastore_t datastore, sr_session_ctx_t **session);

/**
 * @brief Stops current session and releases resources tied to the session.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_session_stop(sr_session_ctx_t *session);


////////////////////////////////////////////////////////////////////////////////
// Data Retrieval API
////////////////////////////////////////////////////////////////////////////////

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
 * @brief Retrieves a single data element stored under provided XPath.
 *
 * If the path identifies an empty leaf, a list or a presence container, the value
 * has no data filled in and its type is set properly (SR_LEAF_EMPTY_T / SR_LIST_T / SR_CONTAINER_PRESENCE_T).
 * In case of leaf-list only one (first) element is returned, you need to use
 * ::sr_get_items / ::sr_get_items_iter to retrieve all of them.
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] path @ref xp_page "XPath" identifier of the data element to be retrieved.
 * @param[out] value Structure containing information about requested element
 * (allocated by the function, can be freed with ::sr_free_val).
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOT_FOUND if the entity is
 * not present in the data tree, or the user does not have read permission to access it).
 */
int sr_get_item(sr_session_ctx_t *session, const char *path, sr_val_t **value);

/**
 * @brief Retrieves an array of data elements stored under provided path XPath
 * (direct children of the entity specified by XPath, non-recursively).
 *
 * When called on a leaf-list, returns all leaf-list elements. When called on
 * a list (with keys provided) or a container, returns all direct children of the
 * list instance / container. If there are nested containers or list entities,
 * the value returned for each of them has no data filled in and the type set
 * properly (SR_CONTAINER_T / SR_LIST_T). The XPaths of these container / list
 * values can be used for subsequent sr_get_items calls. When keys are not
 * provided for a list, it returns all list entities, as for nested lists
 * (can be used to list existing key values of a list).
 *
 * If the user does not have read permission to access certain nodes, these
 * won't be part of the result. SR_ERR_NOT_FOUND will be returned if the element
 * under provided path does not exist in the data tree, element does not contain
 * any nested data, or the user does not have read permission to access it.
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see ::sr_get_items_iter can be used for the same purpose as ::sr_get_items
 * call if you expect thet ::sr_get_items could return too large data sets.
 * ::sr_get_items_iter can also be used for recursive subtree retrieval.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] path @ref xp_page "XPath" identifier of the data element to be retrieved.
 * @param[out] values Array of structures containing information about requested
 * data elements (allocated by the function, can be completely freed with ::sr_free_values).
 * @param[out] value_cnt Number of returned elements in the values array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_items(sr_session_ctx_t *session, const char *path, sr_val_t **values, size_t *value_cnt);

/**
 * @brief Creates an iterator for retrieving of the data elements stored under provided path.
 *
 * If the recursive flag is true, it recursively iterates over all nodes in the
 * data tree, up to the tree leaves. If the recursive is false, it iterates only
 * over the nodes at the path level (over the values that ::sr_get_items would return).
 * You can use this function instead of ::sr_get_items if you expect many data
 * entities on the same level.
 *
 * @see @ref xp_page "XPath Addressing" documentation, or
 * https://tools.ietf.org/html/draft-ietf-netmod-yang-json#section-6.11
 * for XPath syntax used for identification of yang nodes in sysrepo calls.
 *
 * @see ::sr_get_item_next for iterating over returned data elements.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in] path @ref xp_page "XPath" identifier of the data element / subtree to be retrieved.
 * @param[in] recursive Indicates whether only the elements at the path level
 * (recursive == false), or all nested elements (recursive == true) should be returned.
 * @param[out] iter Iterator context that can be used to retrieve individual data
 * elements via ::sr_get_item_next calls. Allocated by the function, should be
 * freed with ::sr_free_val_iter.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_get_items_iter(sr_session_ctx_t *session, const char *path, bool recursive, sr_val_iter_t **iter);

/**
 * @brief Returns the next item from the dataset of provided iterator created
 * by ::sr_get_items_iter call.
 *
 * @param[in] session Session context acquired with ::sr_session_start call.
 * @param[in,out] iter Iterator acquired with ::sr_get_items_iter call.
 * @param[out] value Structure containing information about requested element
 * (allocated by the function, can be freed with ::sr_free_val).
 *
 * @return Error code (SR_ERR_OK on success, SR_ERR_NOTFOUND in case that there
 * are not more items in the dataset).
 */
int sr_get_item_next(sr_session_ctx_t *session, sr_val_iter_t *iter, sr_val_t **value);

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
