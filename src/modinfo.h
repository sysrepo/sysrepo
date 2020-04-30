/**
 * @file modinfo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for modinfo routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
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
#ifndef _MODINFO_H
#define _MODINFO_H

#include <libyang/libyang.h>

#include "common.h"

#define MOD_INFO_DEP     0x01   /* dependency module, its data cannot be changed, but are required for validation */
#define MOD_INFO_INV_DEP 0x02   /* inverse dependency module, its data cannot be changed, but will be validated */
#define MOD_INFO_REQ     0x04   /* required module, its data can be changed and it will be validated */
#define MOD_INFO_TYPE_MASK 0x07 /* just a mask for all module types */

#define MOD_INFO_RLOCK   0x08   /* read-locked module (main DS) */
#define MOD_INFO_WLOCK   0x10   /* write-locked module (main DS) */
#define MOD_INFO_RLOCK2  0x20   /* read-locked module (secondary DS, it can be only read locked) */
#define MOD_INFO_CHANGED 0x40   /* module data were changed */

/**
 * @brief Mod info structure, used for keeping all relevant modules for a data operation.
 */
struct sr_mod_info_s {
    sr_datastore_t ds;          /**< Main datastore we are working with. */
    sr_datastore_t ds2;         /**< Secondary datastore valid only if differs from the main one. Used only for locking. */
    struct lyd_node *diff;      /**< Diff with previous data. */
    struct lyd_node *data;      /**< Data tree. */
    int data_cached;            /**< Whether the data are actually in cache (conn cache READ lock is held). */
    sr_conn_ctx_t *conn;        /**< Associated connection. */

    struct sr_mod_info_mod_s {
        sr_mod_t *shm_mod;      /**< Module SHM structure. */
        uint8_t state;          /**< Module state (flags). */
        const struct lys_module *ly_mod;    /**< Module libyang structure. */

        uint32_t request_id;    /**< Request ID of the published event. */
    } *mods;                    /**< Relevant modules. */
    uint32_t mod_count;         /**< Modules count. */
};

/**
 * @brief Add a module into mod info.
 *
 * @param[in] shm_mod Module SHM structure.
 * @param[in] ly_mod Module libyang structure.
 * @param[in] mod_type Module type.
 * @param[in] mod_req_deps Which dependencies are also to be added.
 * @param[in] mod_info Modified mod info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_add_mod(sr_mod_t *shm_mod, const struct lys_module *ly_mod, int mod_type, int mod_req_deps,
        struct sr_mod_info_s *mod_info);

/**
 * @brief Check permissions of all the modules in a mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] wr Whether to check write or read permissions.
 * @param[in] strict Whether to return error if permission check fails or silently remove it from the modules.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr, int strict);

/**
 * @brief Get next mod_info mod in the order they are present in the data.
 *
 * @param[in] last Last returned mod_info mod, NULL on first call.
 * @param[in] mod_info mod_info structure to use.
 * @param[in] data Data to determine the order.
 * @param[in,out] aux Auxiliary array that tracks returned modules. Allocated on first call, freed when returning NULL.
 * @return Next mod_info mod, NULL if last was returned.
 */
struct sr_mod_info_mod_s *sr_modinfo_next_mod(struct sr_mod_info_mod_s *last, struct sr_mod_info_s *mod_info,
        const struct lyd_node *data, uint32_t **aux);

/**
 * @brief Apply sysrepo edit on mod info data, in the same order.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] edit Sysrepo edit to apply.
 * @param[in] create_diff Whether to also create diff with the original data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff);

/**
 * @brief Merge sysrepo diff to mod info diff.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] new_diff New diff to merge into existing diff in mod_info.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_diff_merge(struct sr_mod_info_s *mod_info, const struct lyd_node *new_diff);

/**
 * @brief Replace mod info data with new data.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in,out] src_data New data to set, are spent.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_replace(struct sr_mod_info_s *mod_info, struct lyd_node **src_data);

/**
 * @brief Validate data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] finish_diff Whether to update diff with possible changes caused by validation.
 * @param[in] sid Sysrepo session ID.
 * @param[out] cb_error_info Callback error info in case an operational subscriber data required
 * because of an instance-identifier retrieval failed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff, sr_sid_t *sid,
        sr_error_info_t **cb_error_info);

/**
 * @brief Add default values into data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] finish_diff Whether to update diff with possible changes of default values.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_add_defaults(struct sr_mod_info_s *mod_info, int finish_diff);

/**
 * @brief Validate operation using modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] op Operation data tree (RPC/action/notification).
 * @param[in] shm_deps Main SHM dependencies of the operation.
 * @param[in] shm_dep_count Main SHM dependency count.
 * @param[in] output Whether this is the output of an operation.
 * @param[in] sid Sysrepo session ID.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[out] cb_error_info Callback error info in case an operational subscriber data required
 * because of an instance-identifier retrieval failed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, sr_mod_data_dep_t *shm_deps,
        uint16_t shm_dep_count, int output, sr_sid_t *sid, uint32_t timeout_ms, sr_error_info_t **cb_error_info);

/**
 * @brief Load data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod_type Types of modules whose data should only be loaded.
 * @param[in] cache Whether it makes sense to use cached data, if available.
 * @param[in] sid Sysrepo session ID.
 * @param[in] request_id XPath of the data request.
 * @param[in] timeout_ms Operational callback timeout in milliseconds.
 * @param[in] opts Get oper data options.
 * @param[out] cb_error_info Callback error info in case an operational subscriber of required data failed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_data_load(struct sr_mod_info_s *mod_info, uint8_t mod_type, int cache, sr_sid_t *sid,
        const char *request_id, uint32_t timeout_ms, sr_get_oper_options_t opts, sr_error_info_t **cb_error_info);

/**
 * @brief Filter data from mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] xpath Selected data.
 * @param[in] session Sysrepo session.
 * @param[out] result Resulting set of matching nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_get_filter(struct sr_mod_info_s *mod_info, const char *xpath, sr_session_ctx_t *session,
        struct ly_set **result);

/**
 * @brief Generate a netconf-config-change notification based on changes in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] session Session to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *session);

/**
 * @brief Store data (persistently) from mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_data_store(struct sr_mod_info_s *mod_info);

/**
 * @brief Reset (unlick SHM files) all candidate data for mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_candidate_reset(struct sr_mod_info_s *mod_info);

/**
 * @brief Free mod info.
 *
 * @param[in] mod_info Mod info to free.
 */
void sr_modinfo_free(struct sr_mod_info_s *mod_info);

#endif
