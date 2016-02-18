/**
 * @defgroup dm Data Manager
 * @{
 * @brief Data manager provides access to schemas and data trees managed by sysrepo. It allows to
 * read, lock and edit the data models.
 * @file data_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 *
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


#ifndef SRC_DATA_MANAGER_H_
#define SRC_DATA_MANAGER_H_

#include "sysrepo.pb-c.h"
#include <libyang/libyang.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "sysrepo.h"
#include "xpath_processor.h"


/**
 * @brief suffix of data file for startup datastore
 */
#define DM_STARTUP_SUFFIX ".startup"

/**
 * @brief suffix of data file for running datastore
 */
#define DM_RUNNING_SUFFIX ".running"

/**
 * @brief Structure that holds the context of an instance of Data Manager.
 */
typedef struct dm_ctx_s dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s dm_session_t;


/**
 * @brief Structure holds data tree related info
 */
typedef struct dm_data_info_s{
    const struct lys_module *module;    /**< pointer to schema file*/
    struct lyd_node *node;              /**< data tree */
#if defined __linux__
    struct timespec timestamp;          /**< timestamp of this copy */
#else
    time_t timestamp;                   /**< timestamp of this copy */
#endif
    bool modified;                      /**< flag denoting whether a change has been made*/
}dm_data_info_t;

/**
 * @brief States of the node in running data store.
 */
typedef enum dm_node_state_e{
    DM_NODE_DISABLED,               /**< Node is not enabled request return not found */
    DM_NODE_ENABLED,                /**< Node is enabled */
    DM_NODE_ENABLED_WITH_CHILDREN,  /**< Node is enabled and all its children are enabled too.*/
}dm_node_state_t;

/**
 * @brief Initializes the data manager context, which will be passed in further
 * data manager related calls.
 * @param [in] schema_search_dir - location where schema files are located
 * @param [in] data_search_dir - location where data files are located
 * @param [out] dm_ctx
 * @return Error code (SR_ERR_OK on success), SR_ERR_IO
 */
int dm_init(const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx);

/**
 * @brief Frees all allocated resources by the provided Data manager context, after
 * calling this function using a session initialized in the context is invalid.
 * @param [in] dm_ctx
 */
void dm_cleanup(dm_ctx_t *dm_ctx);

/**
 * @brief Allocates resources for the session in Data manger.
 * @param [in] dm_ctx
 * @param [in] ds - datastore to which the session is tied.
 * @param [out] dm_session_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_session_start(const dm_ctx_t *dm_ctx, const sr_datastore_t ds, dm_session_t **dm_session_ctx);

/**
 * @brief Frees resources allocated for the session.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx);

/**
 * @brief Returns the structure holding data tree, timestamp and modified flag for the specified module.
 * If the module has been already loaded, the session copy is returned. If not
 * the function tries to load it from file system using ::dm_load_data_tree
 * This structure is needed for edit like calls that can modify the data tree.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] module_name
 * @param [out] data_tree
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
int dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info);

/**
 * @brief Returns the data tree for the specified module. Internally calls ::dm_get_dat_info
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] module_name
 * @param [out] data_tree - @note returned data tree should not be modified. To get editable data_tree use ::dm_get_data_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if the requested data tree is empty, SR_ERR_UNKNOWN_MODEL
 */
int dm_get_datatree(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree);

/**
 * @brief Tests if the schema exists in libyang context. If yes returns the module.
 * Returned module might be used to validate xpath or to create data tree.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision can be NULL
 * @param [out] module
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
int dm_get_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision, const struct lys_module **module);

/**
 * @brief Returns an array that contains information about schemas supported by sysrepo.
 * @param [in] dm_ctx
 * @param [in] dm_session
 * @param [out] schemas
 * @param [out] schema_count
 * @return Error code (SR_ERR_OK on success)
 */
int dm_list_schemas(dm_ctx_t *dm_ctx, dm_session_t *dm_session, sr_schema_t **schemas, size_t *schema_count);

/**
 * @brief Validates the data_trees in session.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success), SR_ERR_VALIDATION_FAILED in case of failure
 */
int dm_validate_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Discards the user made changes. Removes session data tree copies, next
 * call ::dm_get_data_info will load fresh data.
 * @param [in] dm_ctx
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_discard_changes(dm_ctx_t *dm_ctx, dm_session_t *session);

/**
 * @brief Saves the changes to the file system.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success), SR_ERR_COMMIT_FAILED, SR_ERR_IO
 */
int dm_commit(dm_ctx_t *dm_ctx, dm_session_t *session, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Frees memory allocated for error and error xpath stored in session.
 * @param [in] session
 */
void dm_clear_session_errors(dm_session_t *session);

/**
 * @brief Stores the error store into the session. Returns provided error code or
 * SR_ERR_INTERNAL if something failed during the process of storing the error.
 * @param [in] session
 * @param [in] msg - if NULL is passed error message will be generated according to the error code
 * @param [in] err_path - expects allocated path, will be freed by dm_report_error
 * @param [in] rc
 * @return rc or SR_ERR_INTERNAL
 */
int dm_report_error(dm_session_t *session, const char *msg, char *err_path, int rc);

/**
 * @brief Checks if the session contains an error
 * @param [in] session
 * @return True if the session contains an error, false otherwise.
 */
bool dm_has_error(dm_session_t *session);

/**
 * @brief Copies the error message and error xpath to the provided variables.
 * @param [in] session
 * @param [out] error_msg
 * @param [out] err_xpath
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_errors(dm_session_t *session, char **error_msg, char **err_xpath);

/**
 *
 * @param [in] node
 * @return True if state of the node is DM_NODE_ENABLED or DM_NODE_ENABLED_WITH_CHILDREN, false otherwise.
 */
bool dm_is_node_enabled(struct lys_node* node);

/**
 *
 * @param [in] node
 * @return True if the state of the node is DM_NODE_ENABLED_WITH_CHILDREN, false otherwise.
 */
bool dm_is_node_enabled_with_children(struct lys_node* node);

/**
 * @brief Evaluates the state of the node - if it is enabled.
 * @param [in] node
 * @return True if the node is enabled. It might be enabled directly or one any of his parent is in state DM_NODE_ENABLED_WITH_CHILDREN.
 */
bool dm_is_enabled_check_recursively(struct lys_node *node);

/**
 * @brief Sets the state of the node.
 * @param [in] node
 * @param [in] state
 * @return Error code (SR_ERR_OK on success)
 */
int dm_set_node_state(struct lys_node *node, dm_node_state_t state);

/**
 * @brief Returns true if argument is not NULL and session is tied to the running data store.
 * @param [in] session
 * @return
 */
bool dm_is_running_ds_session(dm_session_t *session);

/**@} Data manager*/
#endif /* SRC_DATA_MANAGER_H_ */
