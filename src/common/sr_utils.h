/**
 * @file sr_utils.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>, Pavol Hanzel <pavol.hanzel@pantheon.tech>
 * @brief Sysrepo utility functions API.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
 * Copyright 2018 PANTHEON Tech.
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

#ifndef SR_UTILS_H_
#define SR_UTILS_H_

#include <stdarg.h>
#include <stdio.h>
#include <stdbool.h>
#include <time.h>

#include <libyang/libyang.h>

/** get the larger item */
#define MAX(a, b) ((a) > (b) ? (a) : (b))
/** get the smaller item */
#define MIN(a, b) ((a) < (b) ? (a) : (b))

/** Return main module of a libyang's scheme element. */
#define LYS_MAIN_MODULE(lys_elem)  \
            (lys_elem->module->type ? ((struct lys_submodule *)lys_elem->module)->belongsto : lys_elem->module)


typedef struct dm_data_info_s dm_data_info_t;  /**< forward declaration */
typedef struct sr_list_s sr_list_t;  /**< forward declaration */

/**
 * @brief Internal structure holding information about changes used for notifications
 */
typedef struct sr_change_s {
    sr_change_oper_t oper;      /**< Performed operation */
    struct lys_node *sch_node;  /**< Schema node used for comaparation whether the change matches the request */
    sr_val_t *new_value;        /**< Created, modified, moved value, NULL in case of SR_OP_DELETED */
    sr_val_t *old_value;        /**< Prev value, NULL in case of SR_OP_CREATED, predcessor in case of SR_OP_MOVED */
}sr_change_t;

/**
 * @brief Internal structure used across sysrepo to differentiate between supported variants of API.
 */
typedef enum sr_api_variant_e {
    SR_API_VALUES = 0,
    SR_API_TREES = 1
} sr_api_variant_t;

/**
 * @brief Type of the destination for the print operation.
 */
typedef enum sr_print_type_e {
    SR_PRINT_STREAM,  /**< File stream. */
    SR_PRINT_FD,      /**< File descriptor. */
    SR_PRINT_MEM      /**< Memory buffer. */
} sr_print_type_t;

/**
 * @brief Context for the print operation.
 */
typedef struct sr_print_ctx_s {
    sr_print_type_t type;
    union {
        int fd;
        FILE *stream;
        struct {
            char *buf;
            size_t len;
            size_t size;
        } mem;
    } method;
} sr_print_ctx_t;

/**
 * Callback used to ask if a given subtree should be pruned away.
 */
typedef int (*sr_tree_pruning_cb)(void *pruning_ctx, const struct lyd_node *subtree, bool *prune);

/**
 * @defgroup utils Utility Functions
 * @ingroup common
 * @{
 *
 * @brief Utility functions used in sysrepo sources.
 */

/**
 * @brief Converts byte buffer content to uint32_t number.
 *
 * @param[in] buff pointer to buffer where uint32_t number starts.
 *
 * @return uint32_t number.
 */
uint32_t sr_buff_to_uint32(uint8_t *buff);

/**
 * @brief Converts uint32_t number to byte buffer content.
 *
 * @param[in] number uint32_t value of the number.
 * @param[in] buff pointer to buffer where uint32_t number will be placed.
 */
void sr_uint32_to_buff(uint32_t number, uint8_t *buff);

/**
 * @brief Compares the suffix of the string.
 * @param [in] str
 * @param [in] suffix
 */
bool sr_str_ends_with(const char *str, const char *suffix);

/**
 * @brief Compares the prefix of the string.
 * @param [in] str
 * @param [in] prefix
 */
bool sr_str_begins_with(const char *str, const char *prefix);

/**
 * @brief concatenates two string into newly allocated one.
 * @param [in] str1
 * @param [in] str2
 * @param [out] result
 * @return err_code
 */
int sr_str_join(const char *str1, const char *str2, char **result);

/**
 * @brief Concatenates two file paths into newly allocated one.
 * @param [in] path1
 * @param [in] path2
 * @param [out] result
 * @return err_code
 */
int sr_path_join(const char *path1, const char *path2, char **result);

/**
 * @brief Removes all leading and trailing white-space characters from the input string
 * @param [in] str
 */
void sr_str_trim(char *str);

/**
 * @brief Calculates 32-bit hash from a C-string. Uses *djb2* algorithm from *Dan Bernstein*.
 *
 * @param [in] str String to calculate hash from.
 * @return Hash value.
 */
uint32_t sr_str_hash(const char *str);

/**
 * @brief Print to allocated string. This is an implementation of vasprintf() which is only a GNU/BSD
 * extension and not defined by POSIX, even though it is quite usefull in many cases.
 *
 * @param [out] strp A newly allocated string is returned via this pointer.
 * @param [in] fmt Format string.
 * @param [in] ap Sequence of additional arguments, each containing a value to be used to replace
 *                a format specifier in the format string
 * @return Error code (SR_ERR_OK on success)
 */
int sr_vasprintf(char **strp, const char *fmt, va_list ap);

/**
 * @brief Print to allocated string. This is an implementation of asprintf() which is only a GNU/BSD
 * extension and not defined by POSIX, even though it is quite usefull in many cases.
 *
 * @param [out] strp A newly allocated string is returned via this pointer.
 * @param [in] fmt Format string.
 * @param [in] ... Sequence of additional arguments, each containing a value to be used to replace
 *                 a format specifier in the format string
 * @return Error code (SR_ERR_OK on success)
 */
int sr_asprintf(char **strp, const char *fmt, ...) FORMAT(printf, 2, 3);

/**
 * @brief Copies the first string from the beginning of the xpath up to the first colon,
 * that represents the name of the data file.
 * @param [in] xpath
 * @param [out] namespace
 * @return Error code (SR_ERR_OK on success)
 */
int sr_copy_first_ns(const char *xpath, char **namespace);

/**
 * @brief Returns an allocated C-array of all namespaces found in the given expression.
 *
 * @param [in] xpath
 * @param [out] namespaces
 * @param [out] ns_count
 */
int sr_copy_all_ns(const char *xpath, char ***namespaces, size_t *ns_count);

/**
 * @brief Compares the first namespace of the xpath. If an argument is NULL
 * or does not conatain a namespace it is replaced by an empty string.
 * @param [in] xpath
 * @param [in] ns
 * @return same as strcmp function
 */
int sr_cmp_first_ns(const char *xpath, const char *ns);


/**
 * @brief Creates the file name of the data lock file
 *
 * @param [in] data_search_dir Path to the directory with data files
 * @param [in] module_name Name of the module
 * @param [in] ds Datastore
 * @param [out] file_name Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_lock_data_file_name(const char *data_search_dir, const char *module_name,
        const sr_datastore_t ds, char **file_name);

/**
 * @brief Creates the file name of the persistent data file.
 *
 * @param [in] data_search_dir Path to the directory with data files
 * @param [in] module_name Name of the module
 * @param [out] file_name Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_persist_data_file_name(const char *data_search_dir, const char *module_name, char **file_name);

/**
 * @brief Creates the file name of the persistent data file into the provided buffer.
 *
 * @param [in] data_search_dir Path to the directory with data files.
 * @param [in] module_name Name of the module.
 * @param [in,out] buff Buffer where file name will be written.
 * @param [in] buff_len Size of the buffer.
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_persist_data_file_name_buf(const char *data_search_dir, const char *module_name, char *buff, size_t buff_len);

/**
 * @brief Creates the data file name corresponding to the module_name (schema).
 *
 * Function does not check if the schema name is valid. The file name is
 * allocated on heap and needs to be freed by caller.
 *
 * @param[in] data_search_dir Path to the directory with data files.
 * @param[in] module_name Name of the module.
 * @param[in] ds Datastore that needs to be accessed.
 * @param[out] file_name Allocated file path to the data file.
 *
 * @return err_code (SR_ERR_OK on success, SR_ERR_NOMEM if memory allocation failed).
 */
int sr_get_data_file_name(const char *data_search_dir, const char *module_name,
        const sr_datastore_t ds, char **file_name);

/**
 * @brief Creates the schema file name corresponding to the module_name (schema).
 *
 * Function does not check if the schema name is valid. The file name is
 * allocated on heap and needs to be freed by caller.
 *
 * @param [in] schema_search_dir Path to the directory with schema files.
 * @param [in] module_name Name of the module.
 * @param [in] rev_date if set '@' rev_date is added to the filename
 * @param [in] yang_format flag whether yang or yin filename should be created
 * @param [out] file_name Allocated file path to the schema file.
 *
 * @return err_code (SR_ERR_OK on success, SR_ERR_NOMEM if memory allocation failed).
 */
int sr_get_schema_file_name(const char *schema_search_dir, const char *module_name,
        const char *rev_date, bool yang_format, char **file_name);

/**
 * @brief Sets advisory inter-process file lock.
 *
 * Call close() or ::sr_unlock_fd to unlock an previously acquired lock.
 *
 * @note Multiple locks within the same process are allowed and considered as
 * re-initialization of the previous lock (won't fail nor block).
 *
 * @param[in] fd Descriptor of the file to be locked.
 * @param[in] write TRUE if you are requesting a lock for writing to the file,
 * FALSE if you are requesting a lock just for reading.
 * @param[in] wait TRUE If you want this function to block until lock is acquired,
 * FALSE if you want this function to return an error if the lock cannot be acquired.
 *
 * @return err_code (SR_ERR_OK on success, SR_ERR_LOCKED if wait was set to
 * false and the lock cannot be acquired).
 */
int sr_lock_fd(int fd, bool write, bool wait);

/**
 * @brief Removes advisory inter-process file lock previously acquired by
 * ::sr_lock_fd.
 *
 * @param[in] fd Descriptor of the file to be unlocked.
 *
 * @return err_code (SR_ERR_OK on success).
 */
int sr_unlock_fd(int fd);

/**
 * @brief Sets the file descriptor to non-blocking I/O mode.
 *
 * @param[in] fd File descriptor.
 *
 * @return err_code (SR_ERR_OK on success).
 */
int sr_fd_set_nonblock(int fd);

/**
 * @brief Portable way to retrieve effective user ID and effective group ID of
 * the other end of a unix-domain socket.
 *
 * @param[in] fd File descriptor of a socket.
 * @param[out] uid User ID of the other end.
 * @param[out] gid Group ID of the other end.
 *
 * @return Error code.
 */
int sr_get_peer_eid(int fd, uid_t *uid, gid_t *gid);

/**
 * @brief Saves the data tree into file. Workaround function that adds the root element to data_tree.
 * @param [in] file_name
 * @param [in] data_tree
 * @param [in] format
 * @return err_code
 */
int sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree, LYD_FORMAT format);

/**
 * @brief Check if the set contains the specified object.
 * @param[in] set Set to explore.
 * @param[in] node Object to be found in the set.
 * @param[in] sorted *true* if the items of the set are sorted in the ascending order.
 * @return Index of the object in the set or -1 if the object is not present in the set.
 */
int sr_ly_set_contains(const struct ly_set *set, void *node, bool sorted);

/**
 * @brief Sort items of a libyang set in the ascending order.
 *
 * @param [in] set Libyang set to sort.
 */
int sr_ly_set_sort(struct ly_set *set);

/**
 * @brief Returns *true* if the given schema node could be referenced from a data tree,
 * *false* otherwise.
 *
 * @param [in] node
 */
bool sr_lys_data_node(struct lys_node *node);

/**
 * @brief Get the closest predecessor that may be referenced from a data tree.
 *
 * @param [in] node
 * @param [in] augment True if this node may be from an augment definition.
 */
struct lys_node *sr_lys_node_get_data_parent(struct lys_node *node, bool augment);

/**
 * @brief Wrapper for lyd_parse_fd() that performs file format conversion if required.
 *
 * @param [in] ctx
 * @param [in] fd
 * @param [in] format
 * @param [in] options
 */
struct lyd_node *sr_lyd_parse_fd(struct ly_ctx *ctx, int fd, LYD_FORMAT format, int options);

/**
 * @brief Copies the datatree pointed by root including its siblings.
 * @param [in] root Root of the datatree to be duped.
 * @return duplicated datatree or NULL in case of error
 */
struct lyd_node* sr_dup_datatree(struct lyd_node *root);

/**
 * @brief Duplicates the date tree including its sibling into the provided context
 *
 * @note duplication might fails if the data tree contains a node that uses a schema
 * not loaded in destination context (unresolved instance ids do not cause problem).
 * consider calling \b dm_remove_added_data_trees_by_module_name or \b dm_remove_added_data_trees
 *
 * @param [in] root Data tree to be duplicated
 * @param [in] ctx Destination context where the data tree should be duplicated to
 * @return duplicated data tree using the provided context
 */
struct lyd_node* sr_dup_datatree_to_ctx(struct lyd_node *root, struct ly_ctx *ctx);

/**
 * lyd_unlink wrapper handles the unlink of the root_node
 * @param data_info
 * @param node - must be stored under provided data_info
 * @return err_code
 */
int sr_lyd_unlink(dm_data_info_t *data_info, struct lyd_node *node);

/**
 * @brief Insert node after sibling and fixes the pointer in dm_data_info if needed.
 *
 * @note can be used to insert a top-level node into empty data tree
 *
 * @param [in] data_info
 * @param [in] sibling
 * @param [in] node
 * @return 0 on success
 */
int sr_lyd_insert_after(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node);

/**
 * @brief Insert node before sibling and fixes the pointer in dm_data_info if needed.
 * @param [in] data_info
 * @param [in] sibling
 * @param [in] node
 * @return 0 on success
 */
int sr_lyd_insert_before(dm_data_info_t *data_info, struct lyd_node *sibling, struct lyd_node *node);

/**
 * @brief Converts value type of a libyang's leaf(list) to sysrepo representation
 * @param [in] leaf whose value type is converted
 * @return Converted type (sr_type_t)
 */
sr_type_t sr_libyang_leaf_get_type(const struct lyd_node_leaf_list *leaf);

/**
 * @brief Checks if the provided value can be set to the specified schema node.
 * @param [in] node
 * @param [in] value
 * @return Error code (SR_ERR_OK on success)
 */
int sr_check_value_conform_to_schema(const struct lys_node *node, const sr_val_t *value);

/**
 * @brief Copies value from lyd_node_leaf_list to the sr_val_t.
 * @param [in] leaf input which is copied
 * @param [in] value where the content is copied to
 * @return Error code (SR_ERR_OK on success)
 */
int sr_libyang_leaf_copy_value(const struct lyd_node_leaf_list *leaf, sr_val_t *value);

/**
 * @brief Copies value from lyd_node_anydata to the sr_val_t.
 * @param [in] node input which is copied
 * @param [in] value where the content is copied to
 * @return Error code (SR_ERR_OK on success)
 */
int sr_libyang_anydata_copy_value(const struct lyd_node_anydata *node, sr_val_t *value);

/**
 * @brief Converts sr_val_t to string representation, used in set item.
 * @param [in] value
 * @param [in] schema_node
 * @param [out] out
 * @return
 */
int sr_val_to_str_with_schema(const sr_val_t *value, const struct lys_node *schema_node, char **out);

/**
 * @brief Test whether provided schema node is a list key node
 * @param [in] node
 * @return true if it is a key, false otherwise
 */
bool sr_is_key_node(const struct lys_node *node);

/**
 * @brief Convert API variant type to its string representation.
 *
 * @param [in] api_variant API variant to convert.
 * @return Pointer to a statically allocated string.
 */
char *sr_api_variant_to_str(sr_api_variant_t api_variant);

/**
 * @brief Get API variant type from its string representation.
 *
 * @param [in] api_variant_str API variant string representation.
 */
sr_api_variant_t sr_api_variant_from_str(const char *api_variant_str);

/**
 * @brief Copy and convert content of a libyang node and its descendands into a sysrepo tree.
 *
 * @param [in] node libyang node.
 * @param [in] pruning_cb For each subtree this callback decides if it should be pruned away.
 * @param [in] pruning_ctx Context to pruning callback, opaque to this function.
 * @param [out] sr_tree Returned sysrepo tree.
 */
int sr_copy_node_to_tree(const struct lyd_node *node, sr_tree_pruning_cb pruning_cb, void *pruning_ctx, sr_node_t *sr_tree);

/**
 * @brief Copy and convert content of a libyang node and its descendands into a sysrepo tree chunk.
 *
 * @param [in] node libyang node.
 * @param [in] slice_offset Number of child nodes of the chunk root to skip.
 * @param [in] slice_width Maximum number of child nodes of the chunk root to include.
 * @param [in] child_limit Limit on the number of copied children imposed on each node starting from the 3rd level.
 * @param [in] depth_limit Maximum number of tree levels to copy.
 * @param [in] pruning_cb For each subtree this callback decides if it should be pruned away.
 * @param [in] pruning_ctx Context to pruning callback, opaque to this function.
 * @param [out] sr_tree Returned sysrepo tree.
 */
int sr_copy_node_to_tree_chunk(const struct lyd_node *node, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_tree_pruning_cb pruning_cb, void *pruning_ctx, sr_node_t *sr_tree);

/**
 * @brief Convert a set of libyang nodes into an array of sysrepo trees. For each node a corresponding
 * sysrepo (sub)tree is constructed. It is assumed that the input nodes are not descendands and predecessors
 * of each other! With this assumption the links between the output trees does not need to be considered which
 * significantly decreses the cost of this operation.
 *
 * @param [in] nodes A set of libyang nodes.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation. Can be NULL.
 * @param [in] pruning_cb For each subtree this callback decides if it should be pruned away.
 * @param [in] pruning_ctx Context to pruning callback, opaque to this function.
 * @param [out] sr_trees Returned array of sysrepo trees.
 * @param [out] count Number of returned trees.
 */
int sr_nodes_to_trees(struct ly_set *nodes, sr_mem_ctx_t *sr_mem, sr_tree_pruning_cb pruning_cb, void *pruning_ctx,
        sr_node_t **sr_trees, size_t *count);

/**
 * @brief Convert a set of libyang nodes into an array of sysrepo tree chunks. For each node a corresponding
 * sysrepo (sub)tree chunk is constructed. It is assumed that the input nodes are not descendands and predecessors
 * of each other! With this assumption the links between the output tree chunks does not need to be considered which
 * significantly decreses the cost of this operation.
 *
 * @param [in] nodes A set of libyang nodes.
 * @param [in] slice_offset Number of child nodes of each chunk root to skip.
 * @param [in] slice_width Maximum number of child nodes of each chunk root to include.
 * @param [in] child_limit Limit on the number of copied children imposed on each node starting from the 3rd level.
 * @param [in] depth_limit Maximum number of tree levels to copy.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation. Can be NULL.
 * @param [in] pruning_cb For each subtree this callback decides if it should be pruned away.
 * @param [in] pruning_ctx Context to pruning callback, opaque to this function.
 * @param [out] sr_trees Returned array of sysrepo trees.
 * @param [out] count Number of returned trees.
 * @param [out] chunk_ids IDs of the returned chunks.
 */
int sr_nodes_to_tree_chunks(struct ly_set *nodes, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_mem_ctx_t *sr_mem, sr_tree_pruning_cb pruning_cb, void *pruning_ctx,
        sr_node_t **sr_trees, size_t *count, char ***chunk_ids);

/**
 * @brief Convert a sysrepo tree into a libyang data tree.
 * @note data_tree is extended with the converted tree, not overwritten.
 *
 * @param [in] ly_ctx libyang context.
 * @param [in] sr_tree Sysrepo tree (based on sr_node_t).
 * @param [in] root_xpath XPath referencing the tree root (can be NULL for top-level trees).
 * @param [in] output Is sr_tree an RPC/Action output?
 * @param [out] data_tree libyang data tree that will get extended with the converted sysrepo tree.
 */
int sr_tree_to_dt(struct ly_ctx *ly_ctx, const sr_node_t *sr_tree, const char *root_xpath, bool output,
        struct lyd_node **data_tree);

/**
 * @brief Returns the string name of the datastore
 * @param [in] ds
 * @return Data store name
 */
const char * sr_ds_to_str(sr_datastore_t ds);

/**
 * @brief Frees contents of the sr_val_t structure, does not free the
 * value structure itself.
 */
void sr_free_val_content(sr_val_t *value);

/**
 * @brief Frees array of pointers to sr_val_t. For each element, the
 * sr_free_val is called too.
 *
 * @param[in] values
 * @param[in] count length of array
 */
void sr_free_values_arr(sr_val_t **values, size_t count);

/**
 * Frees array of pointers to sr_val_t, but sr_free_val is called only for indexes in range
 * @param [in] values
 * @param [in] from
 * @param [in] to
 */
void sr_free_values_arr_range(sr_val_t **values, const size_t from, const size_t to);

/**
 * @brief Frees contents of a sysrepo tree, does not free the root node itself.
 */
void sr_free_tree_content(sr_node_t *tree);

/**
 * @brief Frees a single sysrepo node.
 */
void sr_free_node(sr_node_t *node);

/**
 * @brief Add error into the array of detailed error information.
 *
 * @param[in, out] sr_errors Array of detailed error information.
 * @param[in, out] sr_error_cnt Number of errors in the sr_errors array.
 * @param[in] xpath Xpath to the node where the error has been discovered.
 * @param[in] msg_fmt Error message format string.
 */
int sr_add_error(sr_error_info_t **sr_errors, size_t *sr_error_cnt, const char *xpath,
        const char *msg_fmt, ...) FORMAT(printf, 4, 5);

/**
 * @brief Frees an array of detailed error information.
 *
 * @param[in] sr_errors Array of detailed error information.
 * @param[in] sr_error_cnt Number of errors in the sr_errors array.
 */
void sr_free_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt);

/**
 * @brief Frees the content of sr_schema_t structure
 * @param [in] schema
 */
void sr_free_schema(sr_schema_t *schema);

/**
 * @brief Frees the changes array
 * @param [in] changes
 * @param [in] count
 */
void sr_free_changes(sr_change_t *changes, size_t count);

/**
 * @brief Daemonize the process. The process will fork and PID of the original
 * (parent) process will be returned.
 *
 * @param[in] debug_mode Do not fork, Turn on logging to stderr.
 * @param[in] log_level Desired log level.
 * @param[in] pid_file PID file path.
 * @param[out] pid_file_fd File descriptor of opened PID file.
 *
 * @return PID of the original (parent) process, 0 In case of debug mode.
 */
pid_t sr_daemonize(bool debug_mode, int log_level, const char *pid_file, int *pid_file_fd);

/**
 * @brief Sends a signal notifying about initialization success to the parent of
 * the process forked by ::sr_daemonize.
 *
 * @param[in] parent_pid PID of the parent process that is waiting for this signal.
 */
void sr_daemonize_signal_success(pid_t parent_pid);

/**
 * @brief Function calls appropriate function on OS X and other unix/linux systems
 *
 * @param [in] clock_id clock identifier
 * @param [in] ts - time structure to be filled
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_clock_get_time(clockid_t clock_id, struct timespec *ts);

/**
 * @brief Sets data file permissions on provided data file / directory derived from the
 * data access permission of the main data file of the module.
 *
 * @param[in] target_file Target file / directory whose access permissions need to be modified.
 * @param[in] target_is_dir True if target is a directory, false if it is a file.
 * @param[in] data_serach_dir Location of the directory with data files.
 * @param[in] module_name Name of the module whose access permissions are used
 * to derive the permissions for the target file / directory.
 * @param[in] strict TRUE in no errors are allowed during the process of setting permissions,
 * FALSE otherwise.
 *
 * @return Error code.
 */
int sr_set_data_file_permissions(const char *target_file, bool target_is_dir, const char *data_serach_dir,
        const char *module_name, bool strict);

/**
 * @brief Function searches for a schema node based on a DATA path.
 * @param [in] module
 * @param [in] start
 * @param [in] data_path
 * @param [in] output Search output instead of input
 * @param [out] ret Set with matched nodes.
 * @return Error code.
 */
int sr_find_schema_node(const struct lys_module *module, const struct lys_node *start, const char *data_path, bool output,
                        struct ly_set **ret);

/**
 * @brief Create directory and all its parent directories as needed.
 *
 * @param [in] path Path to the directory to create.
 * @param [in] mode Specifies the mode for any newly created directory.
 */
int sr_mkdir_recursive(const char *path, mode_t mode);

/**
 * @brief Returns true if the passed module defines any data-carrying elements and not only data types and identities.
 *
 * @param [in] module
 */
bool sr_lys_module_has_data(const struct lys_module *module);

/**
 * @brief Construct string based on the format and extra arguments,
 * and then print it in the given context.
 *
 * @param [in] print_ctx Print context to use for printing.
 * @param [in] format Format string followed by corresponding set of extra arguments.
 */
int sr_print(sr_print_ctx_t *print_ctx, const char *format, ...) FORMAT(printf, 2, 3);

/**
 * @brief Creates the uri for module with the following pattern:
 * NAMESPACE?module=MODULE_NAME&amp;revision=REVISION&amp;features=FEATURE1,FEATURE2
 * @param [in] module - module to generate uri from
 * @param [out] uri
 * @return Error code (SR_ERR_OK on success)
 */
int sr_create_uri_for_module(const struct lys_module *module, char **uri);

/**
 * @brief Get username from UID.
 *
 * @param [in] uid UID of the user to get the name of.
 * @param [out] username Returned username. Deallocate with \b free.
 */
int sr_get_user_name(uid_t uid, char **username);

/**
 * @brief Lookup UID and primary GID in the password database by username.
 *
 * @param [in] username Name of the user to search for.
 * @param [out] uid ID of the user whose name matches the given username.
 * @param [out] gid ID of the primary group of the matching user.
 */
int sr_get_user_id(const char *username, uid_t *uid, gid_t *gid);

/**
 * @brief Get groupname from GID.
 *
 * @param [in] gid GID of the group to get the name of.
 * @param [out] groupname_p Returned groupname. Deallocate with \b free.
 */
int sr_get_group_name(gid_t gid, char **groupname_p);

/**
 * @brief Lookup GID in the group database by groupname.
 *
 * @param [in] groupname Name of the group to search for.
 * @param [out] gid ID of the group with matching groupname.
 */
int sr_get_group_id(const char *groupname, gid_t *gid);

/**
 * @brief Returns an array of all system groups that the given user is member of.
 *
 * @param [in] username Name of the user to search for in the group database.
 * @param [out] groups Array of groups (their names) that the user is member of.
 * @param [out] group_cnt Number of returned groups.
 */
int sr_get_user_groups(const char *username, char ***groups, size_t *group_cnt);

/**
 * @brief Frees the list and that contains allocated strings (they are freed as well).
 * @param [in] list
 */
void sr_free_list_of_strings(sr_list_t *list);

/**
 * @brief Converts time_t into string formatted as date-and-time type defined in RFC 6991.
 *
 * @param [in] time Time to be coverted into string.
 * @param [out] buff String buffer where time will be written.
 * @param [in] buff_size Size of the string buffer.
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_time_to_str(time_t time, char *buff, size_t buff_size);

/**
 * @brief Converts time string formatted as date-and-time type defined in RFC 6991 into time_t.
 *
 * @param [in] time_str String to be converted into time.
 * @param [out] time Resulting time.
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_str_to_time(char *time_str, time_t *time);

/**@} utils */

/**
 * @brief Clone features
 *
 * Clone the features of a module.
 *
 * @param[in] module_src source module for feature cloning
 * @param[in] module_tgt target module for feature cloning
 *
 * @return Error code (SR_ERR_OK on success)
 */
int sr_features_clone(const struct lys_module *module_src, const struct lys_module *module_tgt);

#endif /* SR_UTILS_H_ */
