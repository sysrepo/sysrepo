/**
 * @defgroup dm Data Manager
 * @{
 * @brief Data manager provides access to schemas and data trees managed by sysrepo. It allows to
 * read, lock and edit the data models.
 * @file data_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
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
#include "connection_manager.h"
#include "module_dependencies.h"
#include "nacm.h"

/**
 * @brief number of supported data stores - length of arrays used in session
 */
#define DM_DATASTORE_COUNT 3

/**
 * @brief Structure holds commit contexts for the purposes of notification
 * session.
 */
typedef struct dm_c_ctxs_s {
    sr_btree_t *tree;      /**< Tree of commit context used for notifications */
    pthread_rwlock_t lock; /**< rwlock to access c_ctxs */
    pthread_mutex_t empty_mutex; /**< guards empty and commits_blocked */
    pthread_cond_t empty_cond;   /**< can be used to wait for empty to be true */
    bool empty;                  /**< flag that is set to true if there is no commit ctx stored */
    bool commits_blocked;        /**< flag that decides whether a new commit context cane be inserted into the tree */
} dm_commit_ctxs_t;

/** defined in data_manager.c */
typedef struct dm_tmp_ly_ctx_s dm_tmp_ly_ctx_t;

/**
 * @brief Data manager context holding loaded schemas, data trees
 * and corresponding locks
 */
typedef struct dm_ctx_s {
    ac_ctx_t *ac_ctx;             /**< Access Control module context */
    np_ctx_t *np_ctx;             /**< Notification Processor context */
    pm_ctx_t *pm_ctx;             /**< Persistence Manager context */
    md_ctx_t *md_ctx;             /**< Module Dependencies context */
    nacm_ctx_t *nacm_ctx;         /**< NACM context */
    cm_connection_mode_t conn_mode;  /**< Mode in which Connection Manager operates */
    char *schema_search_dir;      /**< location where schema files are located */
    char *data_search_dir;        /**< location where data files are located */
    sr_locking_set_t *locking_ctx;/**< lock context for lock/unlock/commit operations */
    bool *ds_lock;                /**< Flags if the ds lock is hold by a session*/
    pthread_mutex_t ds_lock_mutex;/**< Data store lock mutex */
    sr_btree_t *schema_info_tree; /**< Binary tree holding information about schemas */
    pthread_rwlock_t schema_tree_lock;  /**< rwlock for access schema_info_tree */
    dm_commit_ctxs_t commit_ctxs; /**< Structure holding commit contexts and corresponding lock */
    struct timespec last_commit_time;  /**< Time of the last commit */
    dm_tmp_ly_ctx_t *tmp_ly_ctx;  /**< Structure wrapping libyang context that is used to validate/print/parse date
                                   * where the set of required yang module can vary */

} dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s dm_session_t;

/**
 * @brief Structure that holds request processor session.
 */
typedef struct rp_session_s rp_session_t;

/**
 * @brief Holds information related to the schema.
 */
typedef struct dm_schema_info_s {
    char *module_name;                  /**< name of the module the name */
    pthread_rwlock_t model_lock;        /**< module lock:
                                         *  read    - usage of schema, reading of private data in schema,
                                         *  write   - load schema, uninstalling context, modification of private data */
    size_t usage_count;                 /**< number of data copies referencing the module after releasing lock */
    pthread_mutex_t usage_count_mutex;  /**< mutex guarding usage_count variable */
    struct ly_ctx *ly_ctx;              /**< libyang context contains the module and all its dependencies.
                                         * Can be NULL if module has been uninstalled
                                         * during sysrepo-engine lifetime */
    const struct lys_module *module;    /**< Pointer to the module, might be NULL if module has been uninstalled*/
    bool cross_module_data_dependency;  /**< Flag whether data from different module is needed for validation */
    bool has_instance_id;               /**< Flag whether the module contains a node of type instance identifier */
    bool can_not_be_locked;             /**< If true module contains no data and lock_module for the module is NOP */
}dm_schema_info_t;

/**
 * @brief Structure holds data tree related info
 */
typedef struct dm_data_info_s{
    bool rdonly_copy;                   /**< node member is only copy of pointer it must not be freed nor modified */
    dm_schema_info_t *schema;           /**< pointer to schema info */
    struct lyd_node *node;              /**< data tree */
    struct timespec timestamp;          /**< timestamp of this copy (used only if HAVE_ST_MTIM is defined) */
    bool modified;                      /**< flag denoting whether a change has been made*/
    sr_list_t *required_modules;        /**< schemas that needs to be in context to print data */
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
    DM_MOVE_OP,
} dm_operation_t;

/**
 * @brief the stages of commit process
 */
typedef enum dm_commit_state_e {
    DM_COMMIT_STARTED,
    DM_COMMIT_LOAD_MODEL_DEPS,
    DM_COMMIT_LOAD_MODIFIED_MODELS,
    DM_COMMIT_REPLAY_OPS,
    DM_COMMIT_VALIDATE_MERGED,
    DM_COMMIT_NACM,
    DM_COMMIT_NOTIFY_VERIFY,
    DM_COMMIT_WAIT_FOR_NOTIFICATIONS,
    DM_COMMIT_WRITE,
    DM_COMMIT_NOTIFY_APPLY,
    DM_COMMIT_NOTIFY_ABORT,
    DM_COMMIT_FINISHED,
}dm_commit_state_t;
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
            char *str_val;              /**< Alternatively value in string form */
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
 * @brief Holds subscriptions for the particular model
 * used in commit context
 */
typedef struct dm_model_subscription_s {
    dm_schema_info_t *schema_info;      /**< schema info identifying the module to which the subscriptions are tied to */
    sr_list_t *subscriptions;           /**< list of struct received from np */
    struct lys_node **nodes;            /**< array of schema nodes corresponding to the subscription */
    struct lyd_difflist *difflist;      /**< diff list */
    sr_list_t *changes;                 /**< set of changes for the model */
    bool changes_generated;             /**< Flag signalizing that changes has been generated */
    pthread_rwlock_t changes_lock;      /**< Lock guarding the changes member of structure */
}dm_model_subscription_t;

/**
 * @brief A set of changes to be commited (returned by \b lyd_diff) */
typedef struct dm_module_difflist_s {
    dm_schema_info_t *schema_info;      /**< schema info identifying the module to which the difflist is tied to */
    struct lyd_difflist *difflist;      /**< diff list */
} dm_module_difflist_t;

/**
 * @brief Structure holding information used during commit process
 */
typedef struct dm_commit_context_s {
    uint32_t id;                /**< id used for commit identification in notification session */
    pthread_mutex_t mutex;      /**< mutex guarding the acces to the structure */
    dm_commit_state_t state;    /**< state the commit tied to this context is in */
    dm_session_t *session;      /**< session where mereged (user changes + file system state) data trees are stored */
    int *fds;                   /**< opened file descriptors */
    bool *existed;              /**< flag wheter the file for the filedesriptor existed (and should be truncated) before commit*/
    size_t modif_count;         /**< number of modified models fds to be closed*/
    sr_list_t *up_to_date_models; /**< set of module names where the timestamp of the session copy is equal to file system timestamp */
    dm_sess_op_t *operations;   /**< pointer to the list of operations performed in session to be commited */
    size_t oper_count;          /**< number of operation in the operations list */
    sr_btree_t *subscriptions;  /**< binary trees of subscriptions organised per models */
    sr_btree_t *prev_data_trees;/**< data trees in the state before commit */
    rp_session_t *init_session; /**< session that initialized the commit, used for resuming commit once verifiers reply */
    sr_error_info_t *errors;    /**< errors returned by verifiers */
    size_t err_cnt;             /**< number of errors from verifiers */
    sr_list_t *err_subs_xpaths; /**< subscriptions that returned an error */
    bool disabled_config_change;/**< flag whether config change notification are disabled */
    sr_btree_t *difflists;      /**< binary tree of diff-lists for each modified module */
    bool nacm_edited;           /**< flag whether the running NACM configuration was edited. */
    bool in_btree;              /**< set to tree if the context was inserted into btree */
    bool should_be_removed;     /**< flag denoting whether c_ctx can be removed from btree */
    int result;                 /**< result of verify or apply commit phase */
    dm_session_t *backup_session; /**< session with backed up modifications from before the commit */
} dm_commit_context_t;

/**
 * @brief End macro for data child iteration
 */
#define LYD_TREE_DFS_END(START, NEXT, ELEM)                                   \
    /* select element for the next run - children first */                    \
    do {                                                                      \
        (NEXT) = (ELEM)->child;                                                 \
        if ((ELEM)->schema->nodetype & (LYS_LEAF | LYS_LEAFLIST | LYS_ANYXML)) { \
            (NEXT) = NULL;                                                    \
        }                                                                     \
        if (!(NEXT)) {                                                        \
            /* no children */                                                 \
            if ((ELEM) == (START)) {                                          \
                /* we are done, (START) has no children */                    \
                break;                                                        \
            }                                                                 \
            /* try siblings */                                                \
            (NEXT) = (ELEM)->next;                                            \
        }                                                                     \
        while (!(NEXT)) {                                                     \
            /* parent is already processed, go to its sibling */              \
            (ELEM) = (ELEM)->parent;                                          \
            /* no siblings, go back through parents */                        \
            if ((ELEM)->parent == (START)->parent) {                          \
                /* we are done, no next element to process */                 \
                break;                                                        \
            }                                                                 \
            (NEXT) = (ELEM)->next;                                            \
        }                                                                     \
    }while(0)

int dm_schema_info_init(const char *schema_search_dir, dm_schema_info_t **schema_info);

void dm_free_schema_info(void *schema_info);

int dm_load_schema_file(const char *schema_filepath, dm_schema_info_t *si, const struct lys_module **mod);

int dm_load_module_ident_deps_r(md_module_t *module, dm_schema_info_t *si, sr_btree_t *loaded_deps);

int dm_load_module_deps_r(md_module_t *module, dm_schema_info_t *si, sr_btree_t *loaded_deps);

/**
 * @brief The function is called to load the requested module into the context.
 */
const struct lys_module *dm_module_clb(struct ly_ctx *ctx, const char *name, const char *ns, int options, void *user_data);

/**
 * @brief Initializes the data manager context, which will be passed in further
 * data manager related calls.
 * @param [in] ac_ctx Access Control module context
 * @param [in] np_ctx Notification Processor context
 * @param [in] pm_ctx Persistence Manager context
 * @param [in] conn_mode Connection mode
 * @param [in] schema_search_dir - location where schema files are located
 * @param [in] data_search_dir - location where data files are located
 * @param [out] dm_ctx
 * @return Error code (SR_ERR_OK on success), SR_ERR_IO
 */
int dm_init(ac_ctx_t *ac_ctx, np_ctx_t *np_ctx, pm_ctx_t *pm_ctx, cm_connection_mode_t conn_mode,
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
int dm_session_start(dm_ctx_t *dm_ctx, const ac_ucred_t *user_credentials, const sr_datastore_t ds, dm_session_t **dm_session_ctx);

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
 *
 * @note Function acquires and releases read lock for the schema info.
 *
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
 * @brief Tests if the schema exists. If yes returns the module (loads from file system if
 * necessary). Having read lock ensures that model will not be uninstalled from sysrepo.
 * Private schema data can be read and data tree manipulation can be done safely.
 *
 * @note Read-lock is acquired after successful call. Lock must be released by caller:
 * pthread_rwlock_unlock(&schema_info->module_lock)
 *
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNOWN_MODEL
 */
int dm_get_module_and_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info);

/**
 * @brief Same as ::dm_get_module_and_lock however rwlock is locked for writing. With write lock
 * acquired, module can be installed/uninstalled and private data stored in schema
 * can be edited.
 *
 * @note Schema info write lock is acquired on successful return from function. Must be released by caller.
 *
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_module_and_lockw(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info);

/**
 * @brief Retrieves schema info using ::dm_get_module_and_lock. Lock is released. Function can be used to verify
 * that module existed during function execution. To use schema_info afterward, lock must be acquired
 * using ::dm_lock_schema_info or ::dm_lock_schema_info_write.
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [out] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_module_without_lock(dm_ctx_t *dm_ctx, const char *module_name, dm_schema_info_t **schema_info);

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
 * @param [in] submodule_revision if submodule name is set, the exact submodule revision
 * can be set and then module information does not have to be filled at all
 * @param [in] yang_format
 * @param [out] schema
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if the module/submodule or corresponding revision can not be found
 */
int dm_get_schema(dm_ctx_t *dm_ctx, const char *module_name, const char *module_revision, const char *submodule_name, const char *submodule_revision, bool yang_format, char **schema);

/**
 * @brief Validates the data_trees in session.
 *
 * @note Function does not acquire nor release a schema lock.
 *
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
 * @param [in] module_name Optional module name.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_discard_changes(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name);

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
int dm_update_session_data_trees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_list_t **up_to_date_models);

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
 * @brief Fill required modules for all modules loaded in the session for the current session datastore.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_load_session_module_deps(dm_ctx_t *dm_ctx, dm_session_t *session);

/**
 * @brief Loads the data tree which has been modified in the session to the commit context. If the session copy has
 * the same timestamp as the file system file it is copied otherwise, data tree is loaded from file and the changes
 * made in the session are applied.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] c_ctx - commit context
 * @param [in] force_copy_uptodate True if timestamp check of session info datatree and datastore file should be
 * skipped and session info datatree should be always used (otherwise if the timestamp of session datatrees is older
 * than of datastore file, the datatrees are overwritten with data loaded from the datastore file)
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_load_modified_models(dm_ctx_t *dm_ctx, const dm_session_t *session, dm_commit_context_t *c_ctx,
        bool force_copy_uptodate, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Tries to acquire write locks on opened fds
 * @param [in] session
 * @param [in] commit_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_writelock_fds(dm_session_t *session, dm_commit_context_t *commit_ctx);

/**
 * @brief Writes the data trees from commit session stored in commit context into the files.
 * In case of error tries to continue. Does not do a cleanup.
 * @param [in] session to be committed
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_write_files(dm_session_t *session, dm_commit_context_t *c_ctx);

/**
 * @brief Execute NETCONF access control (NACM) to determine if the user is allowed
 * to perform all the data modifications included in the commit.
 *
 * @param [in] nacm_ctx
 * @param [in] session
 * @param [in] c_ctx
 * @param [in] copy_config
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success, SR_ERR_UNAUTHORIZED in case of insufficient access rights)
 */
int dm_commit_netconf_access_control(nacm_ctx_t *nacm_ctx, dm_session_t *session, dm_commit_context_t *c_ctx,
                                     bool copy_config, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Notifies about the changes made within the running commit. It is
 * a post-commit notification - failure do not cause the commit to fail.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] ev type of the notification that should be generated
 * @param [in] c_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_notify(dm_ctx_t *dm_ctx, dm_session_t *session, sr_notif_event_t ev, dm_commit_context_t *c_ctx);

/**
 * @brief Frees all resources allocated in commit context closes
 * modif_count of files.
 */
void dm_free_commit_context(void *commit_ctx);

/**
 * @brief Logs add operation into session operation list. The operation list is used
 * during the commit. Passed allocated arguments are freed in case of error also.
 * @param [in] session
 * @param [in] xpath
 * @param [in] val - must be allocated, will be free with operation list
 * @param [in] str_val
 * @param [in] opts
 * @return Error code (SR_ERR_OK on success)
 */
int dm_add_set_operation(dm_session_t *session, const char *xpath, sr_val_t *val, char *str_val, sr_edit_options_t opts);

/**
 * @brief Logs del operation into session operation list. The operation list is used
 * during the commit. Passed allocated arguments are freed in case of error also.
 * @param [in] session
 * @param [in] xpath
 * @param [in] opts
 * @return Error code (SR_ERR_OK on success)
 */
int dm_add_del_operation(dm_session_t *session, const char *xpath, sr_edit_options_t opts);

/**
 * @brief Logs move operation into session operation list. The operation list is used
 * during the commit. Passed allocated arguments are freed in case of error also.
 * @param [in] session
 * @param [in] xpath
 * @param [in] pos
 * @param [in] rel_item
 * @return Error code (SR_ERR_OK on success)
 */
int dm_add_move_operation(dm_session_t *session, const char *xpath, sr_move_position_t pos, const char *rel_item);

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
 * @param [in] sr_mem
 * @param [out] error_msg
 * @param [out] err_xpath
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_errors(dm_session_t *session, sr_mem_ctx_t *sr_mem, char **error_msg, char **err_xpath);

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
 *
 * @note Function expects that a schema info is locked for reading.
 *
 * @param [in] node
 * @return True if the node is enabled. It might be enabled directly or one any of his parent is in state DM_NODE_ENABLED_WITH_CHILDREN.
 */
bool dm_is_enabled_check_recursively(struct lys_node *node);

/**
 * @brief Returns the hash of a schema node xpath identifier.
 * If NULL is provided as the argument then 0 is returned.
 */
uint32_t dm_get_node_xpath_hash(struct lys_node *node);

/**
 * @brief Returns the depth of any potential instance of this schema node in the data tree.
 * If NULL is provided as the argument then 0 is returned.
 */
uint16_t dm_get_node_data_depth(struct lys_node *node);

/**
 * @brief Sets the state of the node.
 *
 * @note Function expects that a schema info is locked for writing.
 *
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
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success), SR_ERR_LOCKED if the module is locked
 * by other session, SR_ERR_UNAUTHORIZED if the file can no be locked because of permissions.
 */
int dm_lock_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name);

/**
 * @brief Releases the lock.
 *
 * @note Function acquires and releases read lock for the schema info.
 *
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
 *
 * @note Function acquires and releases write lock for the schema info.
 *
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] feature_name
 * @param [in] enable
 * @return Error code (SR_ERR_OK on success), SR_ERR_UNKNONW_MODEL, SR_ERR_INVAL_ARG if the module
 * doesn't contain the feature.
 */
int dm_feature_enable(dm_ctx_t *dm_ctx, const char *module_name, const char *feature_name, bool enable);

/**
 * @brief Tries to load the schema with specified revision.
 *
 * @note Function acquires and releases write lock for the schema info.
 *
 * @param [in] dm_ctx
 * @param [in] session DM session.
 * @param [in] module_name
 * @param [in] revision
 * @param [in] file_name Name of the file that should be used for module installation
 * @param [out] implicitly_installed List of automatically installed modules (import based dependencies).
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND if module
 * is not loaded successfully
 */
int dm_install_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name,
        const char *revision, const char *file_name, sr_list_t **implicitly_installed);

/**
 * @brief Disables module
 * @param [in] dm_ctx
 * @param [in] module_name
 * @param [in] revision
 * @param [out] implicitly_removed List of automatically removed modules (import based dependencies).
 * @return Error code (SR_ERR_OK on success)
 */
int dm_uninstall_module(dm_ctx_t *dm_ctx, const char *module_name, const char *revision,
        sr_list_t **implicitly_removed);

/**
 * @brief Checks whether the module contains any state data.
 *
 * @param [in] ctx DM context.
 * @param [in] module_name Name of the module to be checked.
 * @param [out] res True if there is at least one subtree in the module with state data.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_has_state_data(dm_ctx_t *ctx, const char *module_name, bool *res);

/**
 * @brief Checks whether the module has an enabled subtree.
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param [in] ctx
 * @param [in] module_name - name of the module to be checked
 * @param [out] schema - Match schema, can be NULL
 * @param [out] res - True if there is at least one enabled subtree in the module,
 * False otherwise
 * @return Error code (SR_ERR_OK on success)
 */
int dm_has_enabled_subtree(dm_ctx_t *ctx, const char *module_name, dm_schema_info_t **schema, bool *res);

/**
 * @brief Enables module in running datastore (including copying of the startup data into running).
 * @param [in] ctx DM context.
 * @param [in] session DM session.
 * @param [in] module_name Name of the module to be enabled.
 * @param [in] subscription if the subscription is not NULL SR_EV_ENABLED notification is sent to the subscription.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_enable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name,
        const np_subscription_t *subscription);

/**
 * @brief Enables subtree in running datastore (including copying of the startup data into running).
 * @param [in] ctx DM context.
 * @param [in] session DM session.
 * @param [in] module_name Name of the module where a subtree needs to be enabled.
 * @param [in] xpath XPath identifying the subtree to be enabled.
 * @param [in] subscription if the subscription is not NULL SR_EV_ENABLED notification is sent to the subscription.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_enable_module_subtree_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name, const char *xpath,
        const np_subscription_t *subscription);

/**
 * @brief Disables module in running data store
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param [in] ctx
 * @param [in] session
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
int dm_disable_module_running(dm_ctx_t *ctx, dm_session_t *session, const char *module_name);

/**
 * @brief Copies the content of the module from one datastore to the another.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @param [in] source
 * @param [in] destination
 * @param [in] subscription if the subscription is not NULL SR_EV_ENABLED notification is sent to the subscription.
 * @param [in] nacm_on
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_module(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, sr_datastore_t source, sr_datastore_t destination,
        const np_subscription_t *subscription, bool nacm_on, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Copies all enabled modules from one datastore to the another.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] src
 * @param [in] dst
 * @param [in] nacm_on
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_all_models(dm_ctx_t *dm_ctx, dm_session_t *session, sr_datastore_t src, sr_datastore_t dst, bool nacm_on,
                       sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Validates content of a RPC request or reply.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] rpc_xpath XPath of the RPC.
 * @param [in] args Input/output arguments of the RPC.
 * @param [in] arg_cnt Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_rpc(rp_ctx_t *rp_ctx, rp_session_t *session, const char *rpc_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt);

/**
 * @brief Validates content of a RPC request or reply with arguments represented using sr_node_t.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] rpc_xpath XPath of the RPC.
 * @param [in] args Input/output arguments of the RPC.
 * @param [in] arg_cnt Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_rpc_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *rpc_xpath, sr_node_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt);

/**
 * @brief Validates content of an Action request or reply.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] action_xpath XPath of the Action.
 * @param [in] args Input/output arguments of the Action.
 * @param [in] arg_cnt Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_action(rp_ctx_t *rp_ctx, rp_session_t *session, const char *action_xpath, sr_val_t *args, size_t arg_cnt, bool input,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt);

/**
 * @brief Validates content of an Action request or reply with arguments represented using sr_node_t.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] action_xpath XPath of the Action.
 * @param [in] args Input/output arguments of the Action.
 * @param [in] arg_cnt Number of input/output arguments provided.
 * @param [in] input TRUE if input arguments were provided, FALSE if output.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Input/Output arguments including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Input/Output arguments including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_action_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *action_xpath, sr_node_t *args, size_t arg_cnt, bool input,
                         sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt);

/**
 * @brief Validates content of an event notification request.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] notif_xpath XPath of the notification.
 * @param [in] values Event notification subtree nodes.
 * @param [in] value_cnt Number of items inside the values array.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Event notification data including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Event notification data including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @param [out] res_data_tree Resulting data tree, can be NULL in case that the caller does not need it.
 * @param [out] res_ctx Context of \p res_data_tree in case a temporary one had to be created.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_event_notif(rp_ctx_t *rp_ctx, rp_session_t *session, const char *notif_xpath, sr_val_t *values, size_t value_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt,
        struct lyd_node **res_data_tree, struct ly_ctx **res_ctx);

/**
 * @brief Validates content of an event notification request with data represented using sr_node_t.
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] notif_xpath XPath of the notification.
 * @param [in] trees Event notification subtree nodes.
 * @param [in] tree_cnt Number of items inside the values array.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [out] with_def Event notification data including default values represented as sysrepo values.
 * @param [out] with_def_cnt Number of items inside the *with_def* array.
 * @param [out] with_def_tree Event notification data including default values represented as sysrepo trees.
 * @param [out] with_def_tree_cnt Number of items inside the *with_def_tree* array.
 * @param [out] res_data_tree Resulting data tree, can be NULL in case that the caller does not need it.
 * @param [out] res_ctx Context of \p res_data_tree in case a temporary one had to be created.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_validate_event_notif_tree(rp_ctx_t *rp_ctx, rp_session_t *session, const char *notif_xpath, sr_node_t *trees, size_t tree_cnt,
        sr_mem_ctx_t *sr_mem, sr_val_t **with_def, size_t *with_def_cnt, sr_node_t **with_def_tree, size_t *with_def_tree_cnt,
        struct lyd_node **res_data_tree, struct ly_ctx **res_ctx);

/**
 * @brief Parses event notification with data in XML format (notification->type == NP_EV_NOTIF_DATA_XML) into desired
 * sysrepo format (values or trees).
 * @param [in] rp_ctx RP context.
 * @param [in] session RP session.
 * @param [in] sr_mem Sysrepo memory context to use for output values (can be NULL).
 * @param [in,out] notification Notification to be processed.
 * @param [in] api_variant requested API variant (values/trees).
 * @return Error code (SR_ERR_OK on success)
 */
int dm_parse_event_notif(rp_ctx_t *rp_ctx, rp_session_t *session, sr_mem_ctx_t *sr_mem,
        np_ev_notification_t *notification, const sr_api_variant_t api_variant);

/**
 * @brief Call lyd_new path uses ly_ctx from data_info->schema.
 * @param [in] data_info
 * @param [in] path
 * @param [in] value
 * @param [in] options
 * @return same as libyang's lyd_new_path
 */
struct lyd_node *dm_lyd_new_path(dm_data_info_t *data_info, const char *path, const char *value, int options);

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
 * @brief Copies pointer to the selected data tree (in current datastore) from one session to another, if the module is not
 * loaded in 'from' session, does nothing. You need to be sure that from session's datatrees are not
 * freed before "to" session.
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @param [in] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_create_rdonly_ptr_data_tree(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, dm_schema_info_t *schema_info);

/**
 * @brief Checks if the module is loaded in the session. If it is not loaded
 * in the session and it is loaded in from_session. Copies the data tree.
 * @param [in] dm_ctx
 * @param [in] from_session
 * @param [in] session
 * @param [in] module_name
 * @return Error code (SR_ERR_OK on success)
 */
int dm_copy_if_not_loaded(dm_ctx_t *dm_ctx, dm_session_t *from_session, dm_session_t *session, const char *module_name);

/**
 * @brief Changes the datastore to which the session is tied to. Subsequent operations
 * will work on the selected datastore.
 * @param [in] session
 * @param [in] ds
 */
void dm_session_switch_ds(dm_session_t *session, sr_datastore_t ds);

/**
 * @brief Moves session data trees and operations (for all datastores) from one session to another.
 * @param [in] dm_ctx
 * @param [in] from
 * @param [in] to
 * @param [in] ds
 * @return Error code (SR_ERR_OK on success)
 */
int dm_move_session_tree_and_ops(dm_ctx_t *dm_ctx, dm_session_t *from, dm_session_t *to, sr_datastore_t ds);

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
int dm_get_all_modules(dm_ctx_t *dm_ctx, dm_session_t *session, bool enabled_only, sr_list_t **result);

/**
 * @brief If there is a session copy of the model, return modified flag.
 *
 * @note Function acquires and releases read lock for the schema info.
 *
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] module_name
 * @param [out] res - modified flag to be set.
 * @return Error code (SR_ERR_OK on success)
 */
int dm_is_model_modified(dm_ctx_t *dm_ctx, dm_session_t *session, const char *module_name, bool *res);

/**
 * @brief Used to notify that all commit notifications has been delivered.
 * Call when apply/abort notifications are received.
 * @param [in] dm_ctx
 * @param [in] c_ctx_id
 * @return Error code (SR_ERR_OK on success)
 */
int dm_commit_notifications_complete(dm_ctx_t *dm_ctx, uint32_t c_ctx_id);

/**
 * @brief Looks up commit context identified by id
 * @param [in] dm_ctx
 * @param [in] c_ctx_id
 * @param [out] c_ctx pointer to found c_ctx, NULL if there is no cctx with specified id
 * @return Error code (SR_ERR_OK if no error occurred)
 */
int dm_get_commit_context(dm_ctx_t *dm_ctx, uint32_t c_ctx_id, dm_commit_context_t **c_ctx);

/**
 * @brief Returns the structure containing commit contexts and corresponding lock
 * @param [in] dm_ctx
 * @param [out] commit_ctxs
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_commit_ctxs(dm_ctx_t *dm_ctx, dm_commit_ctxs_t **commit_ctxs);

/**
 * @brief Returns and instance of module dependency context
 * @param [in] dm_ctx
 * @param [out] md_ctx
 *
 * @return Error code (SR_ERR_OK on success)
 *
 */
int dm_get_md_ctx(dm_ctx_t *dm_ctx, md_ctx_t **md_ctx);

/**
 * @brief Tries to lock schema info for read - standard usage.
 *
 * @note Schema info read lock is acquired on successful return from function. Must be released by caller.
 * @note Function may return SR_ERR_UNKNOWN_MODULE if the module has been
 * released meanwhile.
 *
 * @param [in] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_lock_schema_info(dm_schema_info_t *schema_info);

/**
 * @brief Acquires write lock for the provided schema info. With write lock
 * acquired, module can be installed/uninstalled and private data stored in schema
 * can be edited.
 *
 * @note Schema info write lock is acquired on successful return from function. Must be released by caller.
 * @note Function may return SR_ERR_UNKNOWN_MODULE if the module has been
 * released meanwhile.
 *
 * @param [in] schema_info
 * @return Error code (SR_ERR_OK on success)
 */
int dm_lock_schema_info_write(dm_schema_info_t *schema_info);

/**
 * @brief Looks up the nodes by schema node.
 *
 * @param [in] session
 * @param [in] module_name - module name identifying data file
 * @param [in] node - selection node
 * @param [out] res - matched node
 *
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_nodes_by_schema(dm_session_t *session, const char *module_name, const struct lys_node *node, struct ly_set **res);

/**
 * @brief Returns and instance of NACM context
 * @param [in] dm_ctx
 * @param [out] nacm_ctx
 *
 * @return Error code (SR_ERR_OK on success)
 *
 */
int dm_get_nacm_ctx(dm_ctx_t *dm_ctx, nacm_ctx_t **nacm_ctx);

/**
 * @brief Returns pointer to the session's data trees.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [out] session_models
 * @return Error code (SR_ERR_OK on success)
 */
int dm_get_session_datatrees(dm_ctx_t *dm_ctx, dm_session_t *session, sr_btree_t **session_models);

/**
 * @brief Function blocks until all commit ctxs are freed or timeout expires.
 * @param [in] dm_ctx
 * @return Error code (SR_ERR_OK on success)
 */
int dm_wait_for_commit_context_to_be_empty(dm_ctx_t *dm_ctx);

/**
 * @brief Functions prints netconf-config-change-notification into string using tmp_ctx.
 * This approach allows to save the notification to the file even using a context that don't have
 * all schemas used by instance id loaded.
 * @param [in] dm_ctx
 * @param [in] notif
 * @param [out] string
 * @return Error code (SR_ERR_OK on success)
 */
int dm_netconf_config_change_to_string(dm_ctx_t *dm_ctx, struct lyd_node *notif, char **string);
/**@} Data manager*/
#endif /* SRC_DATA_MANAGER_H_ */
