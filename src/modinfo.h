/**
 * @file modinfo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for modinfo routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */
#ifndef _MODINFO_H
#define _MODINFO_H

#include <libyang/libyang.h>

#include "common.h"

#define MOD_INFO_DEP     0x01 /* dependency module, its data cannot be changed, but are required for validation */
#define MOD_INFO_INV_DEP 0x02 /* inverse dependency module, its data cannot be changed, but will be validated */
#define MOD_INFO_REQ     0x04 /* required module, its data can be changed and it will be validated */
#define MOD_INFO_TYPE_MASK 0x07 /* just a mask for all module types */

#define MOD_INFO_RLOCK   0x08 /* read-locked module */
#define MOD_INFO_WLOCK   0x10 /* write-locked module */
#define MOD_INFO_CHANGED 0x20 /* module data were changed */

/**
 * @brief Mod info structure, used for keeping all relevant modules for a data operation.
 */
struct sr_mod_info_s {
    sr_datastore_t ds;          /**< Datastore. */
    struct lyd_node *diff;      /**< Diff with previous data. */
    int dflt_change;            /**< Whether a value default flag was changed. */
    struct lyd_node *data;      /**< Data tree. */
    int data_cached;            /**< Whether the data are actually in cache (conn cache READ lock is held). */
    sr_conn_ctx_t *conn;        /**< Associated connection. */

    struct sr_mod_info_mod_s {
        sr_mod_t *shm_mod;      /**< Module SHM structure. */
        uint8_t state;          /**< Module state (flags). */
        const struct lys_module *ly_mod;    /**< Module libyang structure. */

        uint32_t event_id;      /**< Event ID of the published event. */
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
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr);

/**
 * @brief Apply sysrepo edit on mod info data.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] edit Sysrepo edit to apply.
 * @param[in] create_diff Whether to also create diff with the original data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_edit_apply(struct sr_mod_info_s *mod_info, const struct lyd_node *edit, int create_diff);

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
 * @brief Validate operation using modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] op Operation data tree (RPC/action/notification).
 * @param[in] shm_deps Main SHM dependencies of the operation.
 * @param[in] shm_dep_count Main SHM dependency count.
 * @param[in] output Whether this is the output of an operation.
 * @param[in] sid Sysrepo session ID.
 * @param[out] cb_error_info Callback error info in case an operational subscriber data required
 * because of an instance-identifier retrieval failed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, sr_mod_data_dep_t *shm_deps,
        uint16_t shm_dep_count, int output, sr_sid_t *sid, sr_error_info_t **cb_error_info);

/**
 * @brief Load data for modules in mod info.
 *
 * @param[in] mod_info Mod info to use.
 * @param[in] mod_type Only module types which data should be loaded.
 * @param[in] cache Whether it makes sense to use cached data, if available.
 * @param[in] sid Sysrepo session ID.
 * @param[out] cb_error_info Callback error info in case an operational subscriber of required data failed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_data_load(struct sr_mod_info_s *mod_info, uint8_t mod_type, int cache, sr_sid_t *sid,
        sr_error_info_t **cb_error_info);

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
 * @param[in] sess Sysrepo session.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_modinfo_generate_config_change_notif(struct sr_mod_info_s *mod_info, sr_session_ctx_t *sess);

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
