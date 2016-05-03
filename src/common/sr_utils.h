/**
 * @file sr_utils.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
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

#include <libyang/libyang.h>

typedef struct dm_data_info_s dm_data_info_t;  /**< forward declaration */

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
 * @brief Copies the first string from the beginning of the xpath up to the first colon,
 * that represents the name of the data file.
 * @param [in] xpath
 * @param [out] namespace
 * @return Error code (SR_ERR_OK on success)
 */
int sr_copy_first_ns(const char *xpath, char **namespace);

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
 * @brief Call lyd_new_path if the data info does not contain a node attaches the created node.
 * @param [in] data_info
 * @param [in] ctx
 * @param [in] path
 * @param [in] value
 * @param [in] options
 * @return same as libyang's lyd_new_path
 */
struct lyd_node *sr_lyd_new_path(dm_data_info_t *data_info, struct ly_ctx *ctx,
        const char *path, const char *value, int options);

/**
 * @brief Insert node after sibling and fixes the pointer in dm_data_info if needed.
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
 * @brief Converts libyang enum of YANG built-in types to sysrepo representation
 * @param [in] t
 * @return sr_type_t
 */
sr_type_t sr_libyang_type_to_sysrepo(LY_DATA_TYPE t);

/**
 * @brief Converts sr_val_t to string representation, used in set item
 * @param [in] value
 * @param [in] schema_node
 * @param [out] out
 * @return
 */
int sr_val_to_str(const sr_val_t *value, struct lys_node *schema_node, char **out);

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

/**@} utils */

#endif /* SR_UTILS_H_ */
