/**
 * @defgroup dm Data Manager
 * @{
 * @file data_manager.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Data manager provides access to schemas and data trees manged by sysrepo. It allows to
 * read, lock and edit the data models.
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


#ifndef SRC_DATA_MANAGER_H_
#define SRC_DATA_MANAGER_H_

#include "sysrepo.pb-c.h"
#include <libyang/libyang.h>



/**
 * @brief Structure that holds the context of an instance of Data Manager
 */
typedef struct dm_ctx_s dm_ctx_t;

/**
 * @brief Structure that holds Data Manager's per-session context.
 */
typedef struct dm_session_s dm_session_t;

/**
 * Intializes the data manager context. That will be passed in further
 * session related calls.
 * @param [in] search_dir
 * @param [in] dm_ctx
 * @return err_code
 */
int dm_init(const char *search_dir, dm_ctx_t **dm_ctx);

/**
 * Free all allocated resources by the provided context, after
 * calling this function
 * @param [in] dm_ctx
 * @return err_code
 */
int dm_cleanup(dm_ctx_t *dm_ctx);

//TODO select datastore running/candidate

/**
 * Allocate resources for the Data manager session context.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @return err_code
 */
int dm_session_start(const dm_ctx_t *dm_ctx, dm_session_t **dm_session_ctx);

/**
 * Free resources allocated for the session.
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @return
 */
int dm_session_stop(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx);

/**
 *
 * @param [in] dm_ctx
 * @param [in] dm_session_ctx
 * @param [in] module_name
 * @param [out] module
 * @return
 */
int dm_get_datatree(const dm_ctx_t *dm_ctx, dm_session_t *dm_session_ctx, const char *module_name, struct lyd_node **data_tree);



/**@} Data manager*/
#endif /* SRC_DATA_MANAGER_H_ */
