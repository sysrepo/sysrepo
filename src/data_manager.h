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

#include "sr_common.h"
#include "notification_processor.h"
#include "persistence_manager.h"
#include "xpath_processor.h"

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
#ifdef HAVE_STAT_ST_MTIM
    struct timespec timestamp;          /**< timestamp of this copy */
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
 * @brief Kind of operation that can be logged to session's operation list
 */
typedef enum dm_operation_e {
    DM_SET_OP,
    DM_DELETE_OP,
    DM_MOVE_UP_OP,
    DM_MOVE_DOWN_OP
} dm_operation_t;

/**
 * @brief Structure holding information about operation performed.
 */
typedef struct dm_sess_op_s{
    dm_operation_t op;          /**< Operation kind*/
    bool has_error;             /**< Flag if the operation should be performed during commit*/
    xp_loc_id_t *loc_id;        /**< Location id */
    sr_val_t *val;              /**< Value to perform operation with, can be NULL*/
    sr_edit_options_t options;  /**< Operation edit options */
}dm_sess_op_t;

/**
 * @brief Structure holding information used during commit process
 */
typedef struct dm_commit_context_s {
    dm_session_t *session;      /**< session where mereged (user changes + file system state) data trees are stored */
    int *fds;                   /**< opened file descriptors */
    bool *existed;              /**< flag wheter the file for the filedesriptor existed (and should be truncated) before commit*/
    size_t modif_count;         /**< number of modified models fds to be closed*/
    struct ly_set *up_to_date_models; /**< set of module names where the timestamp of the session copy is equal to file system timestamp */
    dm_sess_op_t *operations;   /**< pointer to the list of operations performed in session to be commited */
    size_t oper_count;          /**< number of operation in the operations list */
} dm_commit_context_t;

/**
 * @brief Initializes the data manager context, which will be passed in further
 * data manager related calls.
 * @param [in] ac_ctx_t Acccess Control module context
 * @param [in] np_ctx Notification Processor context
 * @param [in] pm_ctx Persistence Manager context
 * @param [in] schema_search_dir - location where schema files are located
 * @param [in] data_search_dir - location where data files are located
 * @param [out] dm_ctx
 * @return Error code (SR_ERR_OK on success), SR_ERR_IO
 */
int dm_init(ac_ctx_t *ac_ctx, np_ctx_t *np_ctx, pm_ctx_t *pm_ctx,
        const char *schema_search_dir, const char *data_search_dir, dm_ctx_t **dm_ctx);

/**
 * @brief Frees all allocated resources by the provided Data manager context, after
 * calling this function using a session initialized in the context is invalid.
 * @param [in] dm_ctx
 */
void dm_cleanup(dm_ctx_t *dm_ctx);

/**
 * @brief Allocates resources for the session in Data manger.
 * @param [in] dm_ctx
 * @param [in] user_credentials credentials of the user who this session belongs to
 * @param [in] ds - datastore to which the session is tied.
 * @param [out] dm_session_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_session_start(const dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, const sr_datastore_t ds, dm_session_t **dm_session_ctx);

/**
 * @brief Frees resources allocated for the session.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @return
 */
void dm_session_stop(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx);

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
 * @brief Returns the content of the module or submodule. Currently in yin format. Output schema argument
 * is allocated and must be freed by caller
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] module_revision if NULL is passed the latest revision is returned
 * @param [in] submodule_name To retrieve the content of module NULL can be passed,
 * corresponding revision is selected according to the module revision.
 * @param [in] yang_format
 * @param [out] schema
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if the module/submodule or corresponding revision can not be found
 */
int dm_get_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *module_revision, const char *submodule_name, bool yang_format, char **schema);

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
 * @brief Removes the session copies of the data trees that are not up to date.
 * Subsequent calls will load the fresh state.
 *
 * @param [in] dm_ctx
 * @param [in] session to be updated
 * @param [out] up_to_date_models Set of model names that are up to date an operation
 * can applied on them can be skipped
 *
 * @return Error code (SR_ERR_OK on success)
 */
int dm_update_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, struct ly_set **up_to_date_models);

/**
 * @brief Counts modified models and allocates structures used during commit process if the
 * number of modified models is greater than zero. In case of error all allocated resources
 * are cleaned up.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [out] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_prepare_context(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t **c_ctx);

/**
 * @brief Loads the data tree which has been modified in the session to the commit session. If the session copy has
 * the same timestamp as the file system file it is copied otherwise it is loaded from file.
 * In case of error all files are closed.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] commit_session - session where the data models are loaded (either from file or copied from session)
 * @param [in] fds - array where file descriptor of opened files will be stored
 * @param [in] existed - array where the true is set if the file existed
 * @param [out] up_to_date
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx);

/**
 * @brief Writes the data trees from commit session stored in commit context into the files.
 * In case of error tries to continue. Does not do a cleanup.
 * @param [in] session to be committed
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_write_files(dm_session_t *session, dm_commit_context_t *c_ctx);

/**
 * @brief Frees all resources allocated in commit context closes
 * modif_count of files.
 */
void dm_free_commit_context(dm_ctx_t *dm_ctx, dm_commit_context_t *c_ctx);

/**
 * @brief Logs operation into session operation list. The operation list is used
 * during the commit. Passed allocated arguments are freed in case of error also.
 * @param [in] session
 * @param [in] op
 * @param [in] loc_id - must be allocated, will be freed with operation list
 * @param [in] val - must be allocated, will be free with operation list
 * @param [in] opts
 * @return Error code (SR_ERR_OK on success)
 */
int dm_add_operation(dm_session_t *session, dm_operation_t op, xp_loc_id_t *loc_id, sr_val_t *val, sr_edit_options_t opts);

/**
 * @brief Removes last logged operation in session
 * @param [in] session
 */
void dm_remove_last_operation(dm_session_t *session);

/**
 * @brief Return the operation of the session
 * @param [in] session
 * @param [out] ops
 * @param [out] count
 */
void dm_get_session_operations(dm_session_t *session, dm_sess_op_t **ops, size_t *count);

/**
 * @brief Deletes the operations from session that are marked with error flag
 * @param [in] session
 */
void dm_remove_operations_with_error(dm_session_t *session);

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

/**
 * @brief Locks the module with exclusive lock in provided dm_ctx_t. When the module is locked, the changes
 * can be committed only by the session holding lock. Function does the
 * identity switch.
 *
 * If the model is already locked by the session SR_ERR_OK is returned.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the module is locked
 * by other session, SR_ERR_UNAUTHORIZED if the file can no be locked because of permissions.
 */
int dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *module_name);

/**
 * @brief Releases the lock.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] modul_name
 * @return Error code (SR_ERR_OK on success), SR_ERR_INVAL_ARG if the module is not
 * locked by the session
 */
int dm_unlock_module(dm_ctx_t *dm_ctx, dm_session_t *session, char *modul_name);

/**
 * @brief Acquires locks for all models. If the module can not be locked
 * because of permission it is skipped. In any locking failed no module
 * is locked by dm_lock_data_store.
 * @param [in] dm_ctx
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_lock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session);

/**
 * @brief Releases all locks hold by the session
 * @param [in] dm_ctx
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_unlock_datastore(dm_ctx_t *dm_ctx, dm_session_t *session);

/**
 * @brief Enables or disables the feature state in the module.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] feature_name
 * @param [in] enable
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNONW_MODEL, SR_ERR_INVAL_ARG if the module
 * doesn't contain the feature.
 */
int dm_feature_enable(dm_ctx_t *dm_ctx, const char *module_name, const char *feature_name, bool enable);

/**
 * @brief Tries to load the schema with specified revision. If the module has been
 * uninstalled before sysrepo restart is required and SR_ERR_INTERNAL returned.
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if module
 * is not loaded successfully
 */
int dm_install_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision);

/**
 * @brief Disables module
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision
 * @return Error code (SR_ERR_OK on success)
 */
int dm_uninstall_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision);

/**@} Data manager*/
#endif /* SRC_DATA_MANAGER_H_ */
