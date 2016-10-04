/**
 * @file sr_utils.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo utility functions API.
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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
#include <time.h>

#ifdef __APPLE__
/* OS X get_time */
#include <mach/clock.h>
#include <mach/mach.h>
#define CLOCK_REALTIME CALENDAR_CLOCK
#define CLOCK_MONOTONIC SYSTEM_CLOCK
typedef int clockid_t;
#endif

#include <libyang/libyang.h>

typedef struct dm_data_info_s dm_data_info_t;  /**< forward declaration */

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
 * @brief Compares the suffix of the string, if it matches 0 is returned
 * @param [in] str
 * @param [in] suffix
 * @return
 */
int sr_str_ends_with(const char *str, const char *suffix);

/**
 * @brief concatenates two string into newly allocated one.
 * @param [in] str1
 * @param [in] str2
 * @param [out] result
 * @return err_code
 */
int sr_str_join(const char *str1, const char *str2, char **result);

/**
 * @brief Removes all leading and trailing white-space characters from the input string
 * @param [in] str
 */
void sr_str_trim(char *str);

/**
 * @brief Copies the first string from the beginning of the xpath up to the first colon,
 * that represents the name of the data file.
 * @param [in] xpath
 * @param [out] namespace
 * @return Error code (SR_ERR_OK on success)
 */
int sr_copy_first_ns(const char *xpath, char **namespace);

/**
 * @brief Returns an allocated C-array of all top-most namespaces found in the given expression.
 *
 * @param [in] expr
 * @param [out] namespaces
 * @param [out] namespace_cnt
 */
int sr_copy_first_ns_from_expr(const char *expr, char*** namespaces, size_t *namespace_cnt);

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
 * @return err_code
 */
int sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree);

/**
 * @brief Copies the datatree pointed by root including its siblings.
 * @param [in] root Root of the datatree to be duped.
 * @return duplicated datatree or NULL in case of error
 */
struct lyd_node* sr_dup_datatree(struct lyd_node *root);

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
 * @parma [in] value
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
 * @brief Converts sr_val_t to string representation, used in set item.
 * @param [in] value
 * @param [in] schema_node
 * @param [out] out
 * @return
 */
int sr_val_to_str(const sr_val_t *value, const struct lys_node *schema_node, char **out);

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
 * @param [out] sr_tree Returned sysrepo tree.
 */
int sr_copy_node_to_tree(const struct lyd_node *node, sr_node_t *sr_tree);

/**
 * @brief Copy and convert content of a libyang node and its descendands into a sysrepo tree chunk.
 *
 * @param [in] node libyang node.
 * @param [in] slice_offset Number of child nodes of the chunk root to skip.
 * @param [in] slice_width Maximum number of child nodes of the chunk root to include.
 * @param [in] child_limit Limit on the number of copied children imposed on each node starting from the 3rd level.
 * @param [in] depth_limit Maximum number of tree levels to copy.
 * @param [out] sr_tree Returned sysrepo tree.
 */
int sr_copy_node_to_tree_chunk(const struct lyd_node *node, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_node_t *sr_tree);

/**
 * @brief Convert a set of libyang nodes into an array of sysrepo trees. For each node a corresponding
 * sysrepo (sub)tree is constructed. It is assumed that the input nodes are not descendands and predecessors
 * of each other! With this assumption the links between the output trees does not need to be considered which
 * significantly decreses the cost of this operation.
 *
 * @param [in] nodes A set of libyang nodes.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation. Can be NULL.
 * @param [out] sr_trees Returned array of sysrepo trees.
 * @param [out] count Number of returned trees.
 */
int sr_nodes_to_trees(struct ly_set *nodes, sr_mem_ctx_t *sr_mem, sr_node_t **sr_trees, size_t *count);

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
 * @param [out] sr_trees Returned array of sysrepo trees.
 * @param [out] count Number of returned trees.
 */
int sr_nodes_to_tree_chunks(struct ly_set *nodes, size_t slice_offset, size_t slice_width, size_t child_limit,
        size_t depth_limit, sr_mem_ctx_t *sr_mem, sr_node_t **sr_trees, size_t *count);

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
        const char *msg_fmt, ...);

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
 * @brief Sets correct permissions on provided socket directory according to the
 * data access permission of the YANG module.
 *
 * @param[in] socket_dir Socket directory.
 * @param[in] data_serach_dir Location of the directory with data files.
 * @param[in] module_name Name of the module whose access permissions are used
 * to derive the permissions for the socket directory.
 * @param[in] strict TRUE in no errors are allowed during the process of setting permissions,
 * FALSE otherwise.
 *
 * @return Error code.
 */
int sr_set_socket_dir_permissions(const char *socket_dir, const char *data_serach_dir, const char *module_name, bool strict);

/**
 * @brief Function encapsulates the lys_find_xpath for the use cases where the expected
 * result is one node. If result contains more than one node NULL is returned.
 * @param [in] node
 * @param [in] expr
 * @param [in] options
 * @return matched node or NULL in case of error or result containing multiple nodes
 */
struct lys_node * sr_find_schema_node(const struct lys_node *node, const char *expr, int options);
/**@} utils */

#endif /* SR_UTILS_H_ */
