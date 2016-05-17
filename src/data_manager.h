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
 * @brief Holds information related to the schema
 */
typedef struct dm_schema_info_s {
    const char *module_name;       /**< name of the module the name */
    pthread_rwlock_t model_lock;   /**< module lock used */
}dm_schema_info_t;

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
    DM_MOVE_OP,
} dm_operation_t;

/**
 * @brief Structure holding information about operation performed.
 */
typedef struct dm_sess_op_s{
    dm_operation_t op;          /**< Operation kind*/
    bool has_error;             /**< Flag if the operation should be performed during commit*/
    char *xpath;                /**< Xpath */
    union {
        struct set{
            sr_val_t *val;              /**< Value to perform operation with, can be NULL*/
            sr_edit_options_t options;  /**< Operation edit options */
        } set;
        struct del{
            sr_edit_options_t options;  /**< Operation edit options */
        } del;
        struct mov{
            sr_move_position_t position; /**< Position */
            char *relative_item;         /**< Xpath of item used for relative moves*/
        }mov;
    }detail;
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
 * @param [in] ac_ctx Access Control module context
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
 * the function tries to load it from file system.
 * This structure is needed for edit like calls that can modify the data tree.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] module_name
 * @param [out] info
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
int dm_get_data_info(dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, dm_data_info_t **info);

/**
 * @brief Returns the data tree for the specified module.
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
 * @brief Removes the modified flags from session copies of data trees.
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_remove_modified_flag(dm_session_t *session);

/**
 * @brief Empties the list of operation associated with the session
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_remove_session_operations(dm_session_t *session);

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
 * @brief Loads the data tree which has been modified in the session to the commit context. If the session copy has
 * the same timestamp as the file system file it is copied otherwise, data tree is loaded from file and the changes
 * made in the session are applied.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] c_ctx - commit context
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
 * @brief Notifies about the changes made within the running commit. It is
 * a post-commit notification - failure do not cause the commit to fail.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_notify(dm_ctx_t *dm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx);

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
 * @param [in] xpath
 * @param [in] val - must be allocated, will be free with operation list
 * @param [in] opts
 * @param [in] pos - applicable only with move operation
 * @param [in] rel_item - option of move operation
 * @return Error code (SR_ERR_OK on success)
 */
int dm_add_operation(dm_session_t *session, dm_operation_t op, const char *xpath, sr_val_t *val, sr_edit_options_t opts, sr_move_position_t pos, const char *rel_item);

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
int dm_report_error(dm_session_t *session, const char *msg, const char *err_path, int rc);

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
 * @brief Looks up the schema info structure for the module specified by module name
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_schema_info(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info);

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
int dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name);

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

/**
 * @brief Checks whether the module has an enabled subtree.
 * @param [in] ctx
 * @param [in] module_name - name of the module to be checked
 * @param [out] module - Match module, can be NULL
 * @param [out] res - True if there is at least one enabled subtree in the module,
 * False otherwise
 * @return Error code (SR_ERR_OK on success)
 */
int dm_has_enabled_subtree(dm_ctx_t *ctx, const char *module_name, const struct lys_module **module, bool *res);

/**
 * @brief Enables module in running datastore (including copying of the startup data into running).
 * @param [in] ctx DM context.
 * @param [in] session DM session.
 * @param [in] module_name Name of the module to be enabled.
 * @param [in] module Libyang schema tree pointer. If not known, NULL can be provided.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_enable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const struct lys_module *module);

/**
 * @brief Disables module in running data store
 * @param [in] ctx
 * @param [in] session
 * @param [in] module_name
 * @param [in] module (optional can be NULL)
 * @return Error code (SR_ERR_OK on success)
 */
int dm_disable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const struct lys_module *module);

/**
 * @brief Copies the content of the module from one datastore to the another.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @param [in] source
 * @param [in] destination
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, sr_datastore_t source, sr_datastore_t destination);

/**
 * @brief Copies all enabled modules from one datastore to the another.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] src
 * @param [in] dst
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_all_models(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t src, sr_datastore_t dst);

/**
 * @brief Validates content of a RPC request or reply.
 * @param [in] dm_ctx DM context.
 * @param [in] session DM session.
 * @param [in] rpc_xpath XPath of the RPC.
 * @param [in] args Input/output arguments of the RPC.
 * @param [in] arg_cnt Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_rpc(dm_ctx_t *dm_ctx, dm_session_t *session, const char *rpc_xpath, sr_val_t *args, size_t arg_cnt, bool input);

/**
 * @brief Locks lyctx_lock and call lyd_get_node.
 * @param [in] dm_ctx
 * @param [in] data
 * @param [in] expr
 * @return set of nodes matching expr
 */
struct ly_set *dm_lyd_get_node(dm_ctx_t *dm_ctx, const struct lyd_node *data, const char *expr);

/**
 * @brief Locks lyctx_lock and call lyd_get_node2.
 * @param [in] dm_ctx
 * @param [in] data
 * @param [in] sch_node
 * @return set of instances of sch_node
 */
struct ly_set *dm_lyd_get_node2(dm_ctx_t *dm_ctx, const struct lyd_node *data, const struct lys_node *sch_node);

/**
 * @brief Locks the lyctx lock, subsequently calls lyd_new_path if the data info does not contain a node attaches the created node.
 * @param [in] dm_ctx
 * @param [in] data_info
 * @param [in] ctx
 * @param [in] path
 * @param [in] value
 * @param [in] options
 * @return same as libyang's lyd_new_path
 */
struct lyd_node *dm_lyd_new_path(dm_ctx_t *dm_ctx, dm_data_info_t *data_info, struct ly_ctx *ctx,
        const char *path, const char *value, int options);

/**
 * @brief Locks the lyctx lock, then call lyd_wd_add
 * @param [in] dm_ctx
 * @param [in] lyctx
 * @param [in] root
 * @param [in] options
 * @return Error code
 */
int dm_lyd_wd_add(dm_ctx_t *dm_ctx, struct ly_ctx *lyctx, struct lyd_node **root, int options);

/**
 * @brief Locks the lyctx lock, then call ly_ctx_ge_node
 * @param [in] dm_ctx
 * @param [in] lyctx
 * @param [in] start
 * @param [in] nodeid
 * @return Matched schema node
 */
const struct lys_node *dm_ly_ctx_get_node(dm_ctx_t *dm_ctx, struct ly_ctx *lyctx, const struct lys_node *start, const char *nodeid);

/**
 * @brief Copies all modified data trees (in current datastore) from one session to another.
 * @note Corresponding operations are not copied so the changes may be overwritten by session refresh.
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_modified_session_trees(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to);

/**
 * @brief Copies the selected data tree (in current datastore) from one session to another, if the module is not
 * loaded in 'from' session, does nothing.
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_session_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, const char *module_name);

/**
 * @brief Moves session data trees and operations (in current datastore) from one session to another
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @return Error code (SR_ERR_OK on success)
 */
int dm_move_session_tree_and_ops(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to);

/**
 * @brief Changes the datastore to which the session is tied to. Subsequent operations
 * will work on the selected datastore.
 * @param [in] session
 * @param [in] ds
 * @return Error code (SR_ERR_OK on success)
 */
int dm_session_switch_ds(dm_session_t *session, sr_datastore_t ds);

/**
 * @brief Moves session data trees and operations (for all datastores) from one session to another.
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @return Error code (SR_ERR_OK on success)
 */
int dm_move_session_tree_and_ops_all_ds(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to);

/**
 * @brief Moves data trees from one datastore to another in the session
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] from
 * @param [in] to
 * @return Error code (SR_ERR_OK)
 */
int dm_move_session_trees_in_session(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t from, sr_datastore_t to);

/**
 * @brief Returns the set of all modules.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] enabled_only
 * @param [out] result
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_all_modules(dm_ctx_t *dm_ctx, dm_session_t *session, bool enabled_only, struct ly_set **result);

/**
 * @brief If there is a session copy of the model, return modified flag.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @param [out] res - modified flag to be set.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_is_model_modified(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, bool *res);
/**@} Data manager*/
#endif /* SRC_DATA_MANAGER_H_ */
