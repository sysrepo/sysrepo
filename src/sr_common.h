/**
 * @file sr_common.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo common utilities.
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

#include <linux/socket.h>
#include <sys/types.h>
#include <libyang/libyang.h>

#include "sysrepo.h"
#include "sr_logger.h"
#include "sysrepo.pb-c.h"

#define CHECK_NULL_ARG__INTERNAL(ARG) \
    if (NULL == ARG) { \
        SR_LOG_ERR("NULL value detected for %s argument of %s", #ARG, __FUNCTION__); \
        return SR_ERR_INVAL_ARG; \
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
 * @brief Frees sr_val_t structure
 * @param [in] value
 */
void sr_free_val_t(sr_val_t *value);

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

#endif /* SRC_SR_COMMON_H_ */
