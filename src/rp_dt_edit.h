/**
 * @defgroup rp_edit Request processor data tree create, update & delete helpers 
 * @{
 * @brief 
 * @file rp_dt_edit.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
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

#include "data_manager.h"

/**
 * @brief Deletes item(s) identified by xpath. List key can not be deleted.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] datastore
 * @param [in] xpath
 * @param [in] options
 * @return err_code
 */
int rp_dt_delete_item(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_datastore_t datastore, const char *xpath, const sr_edit_flag_t options);

/**
 * @brief Function can create presence container, list instance, leaf, leaf-list item. If the xpath identifies leaf-list value is appended to the end
 * of the leaf-list. Value of the list key can not be set or changed.
 * @param [in] dm_ctx
 * @param [in] session
 * @param [in] datastore
 * @param [in] xpath
 * @param [in] options
 * @param [in] value the value to be set (xpath inside the structure is ignored), in case of presence container or list instance is ignored can be NULL 
 * @return err_code SR_ERR_OK on success
 */
int rp_dt_set_item(dm_ctx_t *dm_ctx, dm_session_t *session, const sr_datastore_t datastore, const char *xpath, const sr_edit_flag_t options, const sr_val_t *value);

#endif /* RP_DT_EDIT_H */

/**
 * @}
 */
