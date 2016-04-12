/**
 * @file sr_common.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common routines.
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

#ifndef SRC_SR_COMMON_H_
#define SRC_SR_COMMON_H_

/**
 * @defgroup common Common Routines
 * @{
 *
 * @brief This module contains common routines and utilities used across
 * both sysrepo Client Library and Sysrepo Engine.
 */

#include <stdbool.h>
#include <sys/types.h>
#include <stdint.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "sr_constants.h"
#include "sr_logger.h"
#include "sr_btree.h"

#include "sysrepo.pb-c.h"

#define CHECK_NULL_ARG__INTERNAL(ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __FUNCTION__); \
        return SR_ERR_INVAL_ARG; \
    } \

#define CHECK_NULL_ARG_VOID__INTERNAL(ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __FUNCTION__); \
        return; \
    } \

#define CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __FUNCTION__); \
        RC = SR_ERR_INVAL_ARG; \
    } \

#define CHECK_NULL_ARG(ARG) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG) \
    } while(0)

#define CHECK_NULL_ARG2(ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
    } while(0)

#define CHECK_NULL_ARG3(ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
    } while(0)

#define CHECK_NULL_ARG4(ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
        CHECK_NULL_ARG__INTERNAL(ARG4) \
    } while(0)

#define CHECK_NULL_ARG5(ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG__INTERNAL(ARG1) \
        CHECK_NULL_ARG__INTERNAL(ARG2) \
        CHECK_NULL_ARG__INTERNAL(ARG3) \
        CHECK_NULL_ARG__INTERNAL(ARG4) \
        CHECK_NULL_ARG__INTERNAL(ARG5) \
    } while(0)

#define CHECK_NULL_ARG_VOID(ARG) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG) \
    } while(0)

#define CHECK_NULL_ARG_VOID2(ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
    } while(0)

#define CHECK_NULL_ARG_VOID3(ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
    } while(0)

#define CHECK_NULL_ARG_VOID4(ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG4) \
    } while(0)

#define CHECK_NULL_ARG_VOID5(ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG1) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG2) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG3) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG4) \
        CHECK_NULL_ARG_VOID__INTERNAL(ARG5) \
    } while(0)

#define CHECK_NULL_ARG_NORET(RC, ARG) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG) \
    } while(0)

#define CHECK_NULL_ARG_NORET2(RC, ARG1, ARG2) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
    } while(0)

#define CHECK_NULL_ARG_NORET3(RC, ARG1, ARG2, ARG3) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
    } while(0)

#define CHECK_NULL_ARG_NORET4(RC, ARG1, ARG2, ARG3, ARG4) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG4) \
    } while(0)

#define CHECK_NULL_ARG_NORET5(RC, ARG1, ARG2, ARG3, ARG4, ARG5) \
    do { \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG1) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG2) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG3) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG4) \
        CHECK_NULL_ARG_NORET__INTERNAL(RC, ARG5) \
    } while(0)

#define CHECK_NULL_NOMEM_RETURN(ARG) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __FUNCTION__); \
            return SR_ERR_NOMEM; \
        } \
    } while(0)

#define CHECK_NULL_NOMEM_ERROR(ARG, ERROR) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __FUNCTION__); \
            ERROR = SR_ERR_NOMEM; \
        } \
    } while(0)

#define CHECK_NULL_NOMEM_GOTO(ARG, ERROR, LABEL) \
    do { \
        if (NULL == ARG) { \
            SR_LOG_ERR("Unable to allocate memory in %s", __FUNCTION__); \
            ERROR = SR_ERR_NOMEM; \
            goto LABEL; \
        } \
    } while(0)

#define CHECK_RC_MSG_RETURN(RC, MSG) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR_MSG(MSG); \
            return RC; \
        } \
    } while(0)

#define CHECK_RC_LOG_RETURN(RC, MSG, ...) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            return RC; \
        } \
    } while(0)

#define CHECK_RC_MSG_GOTO(RC, LABEL, MSG) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR_MSG(MSG); \
            goto LABEL; \
        } \
    } while(0)

#define CHECK_RC_LOG_GOTO(RC, LABEL, MSG, ...) \
    do { \
        if (SR_ERR_OK != RC) { \
            SR_LOG_ERR(MSG, __VA_ARGS__); \
            goto LABEL; \
        } \
    } while(0)

/**
 * @brief Returns string with name of the provided operation.
 *
 * @param[in] operation Sysrepo operation in GPB enum value format.
 *
 * @return Name of the operation (statically allocated, do not free).
 */
const char *sr_operation_name(Sr__Operation operation);

/**
 * @brief FIFO circular buffer queue context.
 */
typedef struct sr_cbuff_s sr_cbuff_t;

/**
 * @brief Initializes FIFO circular buffer of elements with given size.
 *
 * You can provide initial capacity of the buffer. The buffer automatically
 * enlarges when it's full (it always doubles its capacity).
 *
 * @param[in] initial_capacity Initial buffer capacity in number of elements.
 * @param[in] elem_size Size of one element (in bytes).
 * @param[out] buffer Circular buffer queue context.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_cbuff_init(const size_t initial_capacity, const size_t elem_size, sr_cbuff_t **buffer);

/**
 * @brief Cleans up circular buffer.
 *
 * All memory allocated within provided circular buffer context will be freed.
 *
 * @param[in] buffer Circular buffer context.
 */
void sr_cbuff_cleanup(sr_cbuff_t *buffer);

/**
 * @brief Enqueues an element into circular buffer.
 *
 * @param[in] buffer Circular buffer context.
 * @param[in] item The element to be enqueued (pointer to memory from where
 * the data will be copied to buffer).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_cbuff_enqueue(sr_cbuff_t *buffer, void *item);

/**
 * @brief Dequeues an element from circular buffer.
 *
 * @param[in] buffer Circular buffer queue context.
 * @param[out] item Pointer to memory where dequeued data will be copied.
 *
 * @return TRUE if an element was dequeued, FALSE if the buffer is empty.
 */
bool sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item);

/**
 * @brief Return number of elements currently stored in the queue.
 *
 * @param[in] buffer Circular buffer queue context.
 *
 * @return Number of elements currently stored in the queue.
 */
size_t sr_cbuff_items_in_queue(sr_cbuff_t *buffer);

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
 * @brief Saves the data tree into file. Workaround function that adds the root element to data_tree.
 * @param [in] file_name
 * @param [in] data_tree
 * @return err_code
 */
int sr_save_data_tree_file(const char *file_name, const struct lyd_node *data_tree);

/*
 * @brief Copies the datatree pointed by root including its siblings.
 * @param [in] root
 * @return duplicated datatree or NULL in case of error
 */
struct lyd_node* sr_dup_datatree(struct lyd_node *root);

/* forward declaration */
typedef struct dm_data_info_s dm_data_info_t;

/**
 * lyd_unlink wrapper handles the unlink of the root_node
 * @param data_info
 * @param node - must be stored under provided data_info
 * @return err_code
 */
int sr_lyd_unlink(dm_data_info_t *data_info, struct lyd_node *node);

/**
 * lyd_new wrapper handle the creation of the container or list
 * @param data_info
 * @param parent
 * @param module
 * @param node_name
 * @return created node or NULL in case of error
 */
struct lyd_node *sr_lyd_new(dm_data_info_t *data_info, struct lyd_node *parent, const struct lys_module *module, const char *node_name);

/**
 * lyd_new wrapper handle the creation of the leaf or leaflist
 * @param data_info
 * @param parent
 * @param module
 * @param node_name
 * @param value
 * @return created node or NULL in case of error
 */
struct lyd_node *sr_lyd_new_leaf(dm_data_info_t *data_info, struct lyd_node *parent, const struct lys_module *module, const char *node_name, const char *value);

/**
 * @brief Call lyd_new_path if the data info does not contain a node attaches the created node.
 * @param [in] data_info
 * @param [in] ctx
 * @param [in] path
 * @param [in] value
 * @param [in] options
 * @return same as libyang's lyd_new_path
 */
struct lyd_node *sr_lyd_new_path(dm_data_info_t *data_info, struct ly_ctx *ctx, const char *path, const char *value, int options);

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
 * @brief Allocates and initializes GPB request message.
 *
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_pb_req_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB response message.
 *
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_pb_resp_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB notification message.
 *
 * @param[in] event Notification event type.
 * @param[in] destination Destination (socket path) of the notification.
 * @param[in] subscription_id CLient-local subscription identifier.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_pb_notif_alloc(const Sr__NotificationEvent event, const char *destination,
        const uint32_t subscription_id, Sr__Msg **msg_p);

/**
 * @brief Validates the message according to excepted message type and operation.
 *
 * @param[in] msg Unpacked message.
 * @param[in] type Expected type of the message.
 * @param[in] operation Expected operation of the message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_pb_msg_validate(const Sr__Msg *msg, const Sr__Msg__MsgType type, const Sr__Operation operation);

/**
 * @brief Validates the notification message according to excepted notification event.
 *
 * @param[in] msg Unpacked message.
 * @param[in] event Expected notification event.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_pb_msg_validate_notif(const Sr__Msg *msg, const Sr__NotificationEvent event);

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
 * @brief Allocates and fills gpb structure form sr_val_t.
 * @param [in] value
 * @param [out] gpb_value
 * @return err_code
 */
int sr_dup_val_t_to_gpb(const sr_val_t *value, Sr__Value **gpb_value);

/**
 * @brief Allocates and fills sr_val_t structure from gpb.
 * @param [in] gpb_value
 * @param [out] value
 * @return err_code
 */
int sr_dup_gpb_to_val_t(const Sr__Value *gpb_value, sr_val_t **value);

/**
 * @brief Fills sr_val_t structure from gpb.
 * @param [in] gpb_value
 * @param [out] value
 * @return err_code
 */
int sr_copy_gpb_to_val_t(const Sr__Value *gpb_value, sr_val_t *value);

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
 * @brief Converts sysrepo datastore to GPB datastore.
 *
 * @param [in] sr_ds Sysrepo datastore.
 * @return GPB datastore.
 */
Sr__DataStore sr_datastore_sr_to_gpb(const sr_datastore_t sr_ds);

/**
 * @brief Converts GPB datastore to sysrepo datastore.
 *
 * @param [in] gpb_ds GPB datastore
 * @return Sysrepo datastore.
 */
sr_datastore_t sr_datastore_gpb_to_sr(Sr__DataStore gpb_ds);

/**
 * @brief Converts sysrepo move direction to GPB move direction.
 *
 * @param[in] sr_direction Sysrepo move direction.
 * @return GPB move direction.
 */
Sr__MoveItemReq__MoveDirection sr_move_direction_sr_to_gpb(sr_move_direction_t sr_direction);

/**
 * @brief Converts GPB move direction to sysrepo move direction.
 *
 * @param[in] gpb_direction GPB move direction.
 * @return Sysrepo move direction.
 */
sr_move_direction_t sr_move_direction_gpb_to_sr(Sr__MoveItemReq__MoveDirection gpb_direction);

/**
 * @brief Converts array of sr_schema_t to an array of pointers to GPB schemas.
 *
 * @param [in] sr_schemas Array of sr_schema_t.
 * @param [in] schema_cnt Number of schemas in the array.
 * @param [out] gpb_schemas Array of pointers to GPB schemas (both pointers
 * array and schemas are allocated by the function, should be freed with free()
 * and sr__schema__free_unpacked function).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_schemas_sr_to_gpb(const sr_schema_t *sr_schemas, const size_t schema_cnt, Sr__Schema ***gpb_schemas);

/**
 * @brief Converts array of pointers to GPB schemas to an array of sr_schema_t.
 *
 * @param [in] gpb_schemas Array of pointers to GPB schemas.
 * @param [in] schema_cnt Number of schemas in the array.
 * @param [out] sr_schemas Array of sr_schema_t (allocated by the function,
 * should be freed with ::sr_free_schemas).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_schemas_gpb_to_sr(const Sr__Schema **gpb_schemas, const size_t schema_cnt, sr_schema_t **sr_schemas);

/**
 * @brief Converts sr_val_t to string representation, used in set item
 * @param [in] value
 * @param [in] schema_node
 * @param [out] out
 * @return
 */
int sr_val_to_str(const sr_val_t *value, struct lys_node *schema_node, char **out);

/**
 * @brief Fills detailed error information into a GPB error message.
 *
 * @param[in] error_message Error message (can be NULL). String will be duplicated.
 * @param[in] error_path XPath to node where error occurred (can be NULL). String will be duplicated.
 * @param[in,out] gpb_error GPB message where the error information should be filled in.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_fill_error(const char *error_message, const char *error_path, Sr__Error **gpb_error);

/**
 * @brief Fills detailed error information into an array of pointers to GPB error messages.
 *
 * @param[in] sr_errors Array of detailed error information.
 * @param[in] sr_error_cnt Number of errors in the sr_errors array.
 * @param[out] gpb_errors Array of pointers to GPB error messages (will be allocated).
 * @param[out] gpb_error_cnt Number of errors set to gpb_errors array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_fill_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt, Sr__Error ***gpb_errors, size_t *gpb_error_cnt);

/**
 * @brief Frees an array of detailed error information.
 *
 * @param[in] sr_errors Array of detailed error information.
 * @param[in] sr_error_cnt Number of errors in the sr_errors array.
 */
void sr_free_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt);

/**
 * @brief Creates the file name of the data lock file
 *
 * @param [in] data_search_dir Path to the directory with data files
 * @param [in] module_name Name of the module
 * @param [in] ds Datastore
 * @param [out] file_name Allocated file path
 * @return Error code (SR_ERR_OK on success)
 */
int sr_get_lock_data_file_name(const char *data_search_dir, const char *module_name, const sr_datastore_t ds, char **file_name);

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
int sr_get_data_file_name(const char *data_search_dir, const char *module_name, const sr_datastore_t ds, char **file_name);

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
int sr_get_schema_file_name(const char *schema_search_dir, const char *module_name, const char *rev_date, bool yang_format, char **file_name);

/**
 * @brief Frees the content of sr_schema_t structure
 * @param [in] schema
 */
void sr_free_schema(sr_schema_t *schema);

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
 * @param[in] TRUE If you want this function to block until lock is acquired,
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

/**@} common */

#endif /* SRC_SR_COMMON_H_ */
