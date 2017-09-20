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
 * @param[in] sr_mem Sysrepo memory context. If NULL then standard malloc/calloc/free will be used.
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_req_alloc(sr_mem_ctx_t *sr_mem, const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB response message.
 *
 * @param[in] sr_mem Sysrepo memory context. If NULL then standard malloc/calloc/free will be used.
 * @param[in] session_id ID of session identifying the recipient. Pass 0 if session is not open yet.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_resp_alloc(sr_mem_ctx_t *sr_mem, const Sr__Operation operation, const uint32_t session_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB notification message.
 *
 * @param[in] sr_mem Sysrepo memory context. If NULL then standard malloc/calloc/free will be used.
 * @param[in] type Notification type.
 * @param[in] destination Destination (socket path) of the notification.
 * @param[in] subscription_id CLient-local subscription identifier.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_notif_alloc(sr_mem_ctx_t *sr_mem, const Sr__SubscriptionType type, const char *destination,
        const uint32_t subscription_id, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB notification acknowledgment message.
 *
 * @param[in] sr_mem Sysrepo memory context. If NULL then standard malloc/calloc/free will be used.
 * @param[in] notification Original notification to be acknowledged.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_notif_ack_alloc(sr_mem_ctx_t *sr_mem, Sr__Msg *notification, Sr__Msg **msg);

/**
 * @brief Allocates and initializes GPB internal request message.
 *
 * @param[in] sr_mem Sysrepo memory context. If NULL then standard malloc/calloc/free will be used.
 * @param[in] operation Requested operation.
 * @param[out] msg GPB message.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_internal_req_alloc(sr_mem_ctx_t *sr_mem, const Sr__Operation operation, Sr__Msg **msg);

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
 * @param[in] type Expected notification type.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_msg_validate_notif(const Sr__Msg *msg, const Sr__SubscriptionType type);

/**
 * @brief Allocates and fills gpb structure from sr_val_t.
 * @param [in] value
 * @param [out] gpb_value
 * @return err_code
 */
int sr_dup_val_t_to_gpb(const sr_val_t *value, Sr__Value **gpb_value);

/**
 * @brief Allocates and fills sr_val_t structure from gpb.
 *
 * @param[in] sr_mem Sysrepo memory context to use for memory allocation.
 *                   If NULL then the standard malloc/calloc are used.
 * @param [in] gpb_value
 * @param [out] value
 * @return err_code
 */
int sr_dup_gpb_to_val_t(sr_mem_ctx_t *sr_mem, const Sr__Value *gpb_value, sr_val_t **value);

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
 * @param[in] sr_mem Sysrepo memory context to use for memory allocation.
 *                   If NULL then the standard malloc/calloc are used.
 * @param[in] gpb_values GPB array of pointers to values.
 * @param[in] gpb_value_cnt Number of values in the input array.
 * @param[out] sr_values Array of sysrepo values.
 * @param[out] sr_value_cnt Number of values in the output array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_values_gpb_to_sr(sr_mem_ctx_t *sr_mem, Sr__Value **gpb_values, size_t gpb_value_cnt, sr_val_t **sr_values,
        size_t *sr_value_cnt);

/**
 * @brief Allocates and copies tree data from the sysrepo tree-representation (based on sr_node_t) into
 * the GPB tree-representation (based on Sr__Node).
 *
 * @param [in] sr_tree Sysrepo tree.
 * @param [out] gpb_tree GPB tree.
 * @return err_code
 */
int sr_dup_tree_to_gpb(const sr_node_t *sr_tree, Sr__Node **gpb_tree);

/**
 * @brief Allocates and copies tree data from the GPB tree-representation (based on Sr__Node) into
 * the sysrepo tree-representation (based on sr_node_t).
 *
 * @param[in] sr_mem Sysrepo memory context to use for memory allocation.
 *                   If NULL then the standard malloc/calloc are used.
 * @param [in] gpb_tree GPB tree.
 * @param [out] sr_tree Sysrepo tree.
 * @return err_code
 */
int sr_dup_gpb_to_tree(sr_mem_ctx_t *sr_mem, const Sr__Node *gpb_tree, sr_node_t **sr_tree);

/**
 * @brief Fill sysrepo tree content from gpb.
 * @param [in] gpb_tree
 * @param [out] sr_tree
 * @return err_code
 */
int sr_copy_gpb_to_tree(const Sr__Node *gpb_tree, sr_node_t *sr_tree);

/**
 * @brief Copies and transforms an array of sysrepo trees into the array of GPB-represented trees.
 *
 * @param[in] sr_trees Array of sysrepo trees.
 * @param[in] sr_tree_cnt Number of trees.
 * @param[out] gpb_trees array of GPB trees.
 * @param[out] gpb_tree_cnt Number of GPB trees as returned in gpb_trees.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_trees_sr_to_gpb(const sr_node_t *sr_trees, const size_t sr_tree_cnt, Sr__Node ***gpb_trees, size_t *gpb_tree_cnt);

/**
 * @brief Copies and transforms an array of GPB trees into the array of sysrepo-represented trees.
 *
 * @param[in] sr_mem Sysrepo memory context to use for memory allocation.
 *                   If NULL then the standard malloc/calloc are used.
 * @param[in] gpb_trees array of GPB trees.
 * @param[in] gpb_tree_cnt Number of GPB trees.
 * @param[out] sr_trees Array of sysrepo trees.
 * @param[out] sr_tree_cnt Number of sysrepo trees as returned in sr_trees.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_trees_gpb_to_sr(sr_mem_ctx_t *sr_mem, Sr__Node **gpb_trees, size_t gpb_tree_cnt, sr_node_t **sr_trees, size_t *sr_tree_cnt);

/**
 * @brief Fills the gpb structures from the set of changes
 * @param [in] sr_changes
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL then the standard malloc/calloc are used.
 * @param [out] changes
 * @param [out] gpb_count
 * @return Error code (SR_ERR_OK on success)
 */
int sr_changes_sr_to_gpb(sr_list_t *sr_changes, sr_mem_ctx_t *sr_mem, Sr__Change ***changes, size_t *gpb_count);

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
 * @brief Converts GPB change operation to sysrepo change
 *
 * @param [in] gpb_ch
 * @return Sysrepo change operation
 */
sr_change_oper_t sr_change_op_gpb_to_sr(Sr__ChangeOperation gpb_ch);

/**
 * @brief Converts sysrepo change to GPB change operation
 *
 * @param [in] sr_ch
 * @return GPB change operation
 */
Sr__ChangeOperation sr_change_op_sr_to_gpb(sr_change_oper_t sr_ch);

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
 * @brief Converts GPB subscription type to its string representation.
 *
 * @param[in] type GPB subscription type.
 * @return Pointer to statically allocated string with the subscription type name.
 */
char *sr_subscription_type_gpb_to_str(Sr__SubscriptionType type);

/**
 * @brief Converts subscription type string to its GPB enum representation.
 *
 * @param[in] type_name String name of the subscription type.
 * @return GPB subscription type.
 */
Sr__SubscriptionType sr_subsciption_type_str_to_gpb(const char *type_name);

/**
 * @brief Converts notification event type from GPB enum to string representation.
 *
 * @param[in] event GPB notification event type.
 * @return Pointer to statically allocated string with the event type name.
 */
char *sr_notification_event_gpb_to_str(Sr__NotificationEvent event);

/**
 * @brief Converts notification event type from sysrepo enum to string representation.
 *
 * @param[in] event Sysrepo notification event type.
 * @return Pointer to statically allocated string with the event type name.
 */
char *sr_notification_event_sr_to_str(sr_notif_event_t event);

/**
 * @brief Converts notification event type from sysrepo enum to its GPB enum representation
 * @param [in] event Syrepo notification event type
 * @return GPB notification event type
 */
Sr__NotificationEvent sr_notification_event_sr_to_gpb(sr_notif_event_t event);

/**
 * @brief Converts notification event type string to its GPB enum representation.
 *
 * @param[in] event_name String name of the notification event type.
 * @return GPB notification event type.
 */
Sr__NotificationEvent sr_notification_event_str_to_gpb(const char *event_name);

/**
 * @brief Converts notification event from GPB to sysrepo type.
 *
 * @param[in] event GPB notification event.
 * @return Sysrepo notification event type.
 */
sr_notif_event_t sr_notification_event_gpb_to_sr(Sr__NotificationEvent event);

/**
 * @brief Converts event notification type from GPB to sysrepo type.
 *
 * @param[in] ev_notif_type GPB event notification type.
 * @return Sysrepo event notification type.
 */
sr_ev_notif_type_t sr_ev_notification_type_gpb_to_sr(Sr__EventNotifReq__NotifType ev_notif_type);

/**
 * @brief Converts Sysrepo API variant type to its GPB enum representation.
 *
 * @param[in] api_variant API variant type to convert.
 * @return GPB API variant type.
 */
Sr__ApiVariant sr_api_variant_sr_to_gpb(sr_api_variant_t api_variant);

/**
 * @brief Converts API variant type from GPB to sysrepo type.
 *
 * @param[in] api_variant_gpb GPB API variant type.
 * @return Sysrepo API variant type.
 */
sr_api_variant_t sr_api_variant_gpb_to_sr(Sr__ApiVariant api_variant_gpb);

/**
 * @brief Converts module state type from sysrepo enum to string representation.
 *
 * @param[in] state Sysrepo module state type.
 * @return Pointer to statically allocated string with the event type name.
 */
char *sr_module_state_sr_to_str(sr_module_state_t state);

/**
 * @brief Converts module state type from sysrepo enum to its GPB enum representation
 * @param [in] state Syrepo module state type
 * @return GPB module state type
 */
Sr__ModuleState sr_module_state_sr_to_gpb(sr_module_state_t state);

/**
 * @brief Converts module state type from GPB to sysrepo type.
 *
 * @param[in] state GPB module state type.
 * @return Sysrepo module state type.
 */
sr_module_state_t sr_module_state_gpb_to_sr(Sr__ModuleState state);

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
 * @param[in] sr_mem Sysrepo memory context to use for memory allocation.
 *                   If NULL then the standard malloc/calloc are used.
 * @param [in] gpb_schemas Array of pointers to GPB schemas.
 * @param [in] schema_cnt Number of schemas in the array.
 * @param [out] sr_schemas Array of sr_schema_t (allocated by the function,
 * should be freed with ::sr_free_schemas).
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_schemas_gpb_to_sr(sr_mem_ctx_t *sr_mem, const Sr__Schema **gpb_schemas, const size_t schema_cnt, sr_schema_t **sr_schemas);

/**
 * @brief Fills detailed error information into a GPB error message.
 *
 * @param[in] error_message Error message (can be NULL). String will be duplicated.
 * @param[in] error_path XPath to node where error occurred (can be NULL). String will be duplicated.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL then the standard malloc/calloc are used.
 * @param[in,out] gpb_error GPB message where the error information should be filled in.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_fill_error(const char *error_message, const char *error_path, sr_mem_ctx_t *sr_mem, Sr__Error **gpb_error);

/**
 * @brief Fills detailed error information into an array of pointers to GPB error messages.
 *
 * @param[in] sr_errors Array of detailed error information.
 * @param[in] sr_error_cnt Number of errors in the sr_errors array.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL then the standard malloc/calloc are used.
 * @param[out] gpb_errors Array of pointers to GPB error messages (will be allocated).
 * @param[out] gpb_error_cnt Number of errors set to gpb_errors array.
 *
 * @return Error code (SR_ERR_OK on success).
 */
int sr_gpb_fill_errors(sr_error_info_t *sr_errors, size_t sr_error_cnt, sr_mem_ctx_t *sr_mem, Sr__Error ***gpb_errors,
        size_t *gpb_error_cnt);

/**@} gpb_wrappers */

#endif /* SR_PROTOBUF_H_ */
