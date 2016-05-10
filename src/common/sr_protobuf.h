/**
 * @file sr_protobuf.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo Google Protocol Buffers conversion functions API.
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

#ifndef SR_PROTOBUF_H_
#define SR_PROTOBUF_H_

#include "sysrepo.pb-c.h"
#include "sr_common.h"

/**
 * @defgroup gpb_wrappers Protocol Buffers Wrappers
 * @ingroup common
 * @{
 *
 * @brief Functions used for wrapping and manipulation with Google Protocol Buffer structures.
 */

/**
 * @brief Returns string with name of the provided operation in GPB format.
 *
 * @param[in] operation Sysrepo operation in GPB enum value format.
 *
 * @return Name of the operation (statically allocated, do not free).
 */
const char *sr_gpb_operation_name(Sr__Operation operation);

/**
 * @brief Allocates and initializes GPB request message.
 *
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_req_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB response message.
 *
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_resp_alloc(const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

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
int sr_gpb_notif_alloc(const Sr__NotificationEvent event, const char *destination,
        const uint32_t subscription_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB internal request message.
 *
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_internal_req_alloc(const Sr__Operation operation, Sr__Msg **msg);

/**
 * @brief Validates the message according to excepted message type and operation.
 *
 * @param[in] msg Unpacked message.
 * @param[in] type Expected type of the message.
 * @param[in] operation Expected operation of the message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_msg_validate(const Sr__Msg *msg, const Sr__Msg__MsgType type, const Sr__Operation operation);

/**
 * @brief Validates the notification message according to excepted notification event.
 *
 * @param[in] msg Unpacked message.
 * @param[in] event Expected notification event.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_msg_validate_notif(const Sr__Msg *msg, const Sr__NotificationEvent event);

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
 * @brief Copies values from sysrepo values array to GPB array of pointers to values.
 * GPB values will be allocated by this function and should be freed by caller.
 *
 * @param[in] sr_values Array of sysrepo values.
 * @param[in] sr_value_cnt Number of values in the input array.
 * @param[out] gpb_values GPB array of pointers to values.
 * @param[out] gpb_value_cnt Number of values in the output array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_values_sr_to_gpb(const sr_val_t *sr_values, const size_t sr_value_cnt, Sr__Value ***gpb_values, size_t *gpb_value_cnt);

/**
 * @brief Copies values from GPB array of pointers to values to sysrepo values array.
 *
 * @param[in] gpb_values GPB array of pointers to values.
 * @param[in] gpb_value_cnt Number of values in the input array.
 * @param[out] sr_values Array of sysrepo values.
 * @param[out] sr_value_cnt Number of values in the output array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_values_gpb_to_sr(Sr__Value **gpb_values, size_t gpb_value_cnt, sr_val_t **sr_values, size_t *sr_value_cnt);

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
Sr__MoveItemReq__MovePosition sr_move_position_sr_to_gpb(sr_move_position_t sr_direction);

/**
 * @brief Converts GPB move direction to sysrepo move direction.
 *
 * @param[in] gpb_direction GPB move direction.
 * @return Sysrepo move direction.
 */
sr_move_position_t sr_move_direction_gpb_to_sr(Sr__MoveItemReq__MovePosition gpb_direction);

/**
 * @brief Converts GPB notification event type to its string representation.
 *
 * @param[in] event GPB event type.
 * @return Pointer to statically allocated string with the event name.
 */
char *sr_event_gpb_to_str(Sr__NotificationEvent event);

/**
 * @brief Converts notification event type string to its GPB enum representation.
 *
 * @param[in] event_name String name of the event.
 * @return GPB event type.
 */
Sr__NotificationEvent sr_event_str_to_gpb(const char *event_name);

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

/**@} gpb_wrappers */

#endif /* SR_PROTOBUF_H_ */
