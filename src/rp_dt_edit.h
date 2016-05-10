/**
 * @defgroup rp_edit Data tree edit helpers
 * @ingroup rp
 * @{
 * @brief Function that can create, modify delete nodes or move lists.
 * @file rp_dt_edit.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 *
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

#ifndef RP_DT_EDIT_H
#define RP_DT_EDIT_H

#include "request_processor.h"
#include "data_manager.h"

/**
 * @brief Validates the xpath and then deletes item(s) identified by xpath.
 * List key can not be deleted. (if attempted SR_ERR_INVAL_ARG is returned)
 * Non-empty list and container can not be deleted with SR_EDIT_NON_RECURSIVE flag
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] options If the nodes can not be delete because of the option SR_ERR_DATA_MISSING or SR_ERR_DATA_EXISTS is returned
 * @return Error code (SR_ERR_OK on success) SR_ERR_DATA_MISSING, SR_ERR_DATA_EXISTS, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options);

/**
 * @brief Function validates the xpath and then creates presence container, list instance, leaf, leaf-list item. If the xpath identifies leaf-list value
 * it is appended to the end of the leaf-list. Value of the list key can not be set or changed. To create a list use
 * xpath including all list keys.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] options If the node can not be created because of the option SR_ERR_DATA_EXISTS or SR_ERR_DATA_MISSING is returned
 * @param [in] value the value to be set (xpath inside the structure is ignored), in case of presence container or list instance is ignored can be NULL
 * @return Error code (SR_ERR_OK on success) SR_ERR_DATA_MISSING, SR_ERR_DATA_EXISTS, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, const sr_edit_flag_t options, const sr_val_t *value);

/**
 * @brief Move the list instance into selected direction. If the list instance doesn't exists or the list is not user-ordered SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] position
 * @param [in] relative_item
 * @return Error code (SR_ERR_OK on success) SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_move_list(dm_ctx_t *dm_ctx, dm_session_t *session, const char *xpath, sr_move_position_t position, const char *relative_item);

/**
 * @brief Wraps ::rp_dt_move_list call, in case of success logs the operation to the session's operation list.
 * @param [in] rp_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] position
 * @param [in] relative_item
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_move_list_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_move_position_t position, const char *relative_item);

/**
 * @brief Wraps ::rp_dt_set_item call. In case of success logs the operation to the session's operation list.
 * @param [in] rp_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] val
 * @param [in] opt
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_set_item_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_val_t *val, sr_edit_options_t opt);

/**
 * @brief Wraps ::rp_dt_delete_item call. In in case of success logs the operation to the session's operation list.
 * @param [in] rp_ctx
 * @param [in] session
 * @param [in] xpath
 * @param [in] opts
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_delete_item_wrapper(rp_ctx_t *rp_ctx, rp_session_t *session, const char *xpath, sr_edit_options_t opts);

/**
 * @brief Saves the changes made in the session to the file system. To make sure that only one commit
 * can be in progress at the same time commit_lock in rp_ctx is used. To solve potential
 * conflict with sysrepo library, each individual data file is locked. In case of
 * failure to lock data file, the commit process is stopped and SR_ERR_COMMIT_FAILED is returned.
 * The commit process can be divided into 5 steps:
 * - validation of modified data trees (in case of error SR_ERR_VALIDATION_FAILED is returned),
 * after successful validation commit_lock is acquired.
 * - initialization of the commit session where all modified models are loaded
 * from file system
 * - operation made in session are applied to the commit session
 * - validate commit_session's data trees because the merge of the session changes
 * may cause invalidity
 * - write commit session's data trees to the file system
 * @param [in] rp_ctx
 * @param [in] session
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success), SR_ERR_COMMIT_FAILED, SR_ERR_VALIDATION_FAILED, SR_ERR_IO
 */
int rp_dt_commit(rp_ctx_t *rp_ctx, rp_session_t *session, sr_error_info_t **errors, size_t *err_cnt);

/**
 * @brief Tries to merge the current state of session with the file system change.
 * Changes that can not be merged with current data store state are skipped and
 * corresponding operations are deleted from session.
 * @param [in] rp_ctx
 * @param [in] session
 * @param [out] errors
 * @param [out] err_cnt
 * @return Error code (SR_ERR_OK on success) SR_ERR_INTERNAL if some operation can not
 * be merged
 */
int rp_dt_refresh_session(rp_ctx_t *rp_ctx, rp_session_t *session, sr_error_info_t **errors, size_t *err_cnt);
#endif /* RP_DT_EDIT_H */

/**
 * @}
 */
