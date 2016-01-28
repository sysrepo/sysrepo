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
#include "sr_logger.h"
#include "sysrepo.pb-c.h"

/** Maximum size of a GPB message. */
#define SR_MAX_MSG_SIZE ((SIZE_MAX < UINT32_MAX) ? SIZE_MAX : UINT32_MAX)

/** Size of the preamble sent before each sysrepo GPB message. */
#define SR_MSG_PREAM_SIZE sizeof(uint32_t)

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

/**
 * @brief Frees datatree pointed by root including its siblings.
 * @param [in] root
 */
void sr_free_datatree(struct lyd_node *root);

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
 * @brief Portable way to retrieve effective user ID and group ID of the
 * other end of a unix-domain socket.
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
 * should be freed with ::sr_free_schemas_t).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_schemas_gpb_to_sr(const Sr__Schema **gpb_schemas, const size_t schema_cnt, sr_schema_t **sr_schemas);

/**@} common */

#endif /* SRC_SR_COMMON_H_ */
