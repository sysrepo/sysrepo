/**
 * @file modinfo.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for modinfo routines
 *
 * @copyright
 * Copyright (c) 2019 CESNET, z.s.p.o.
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

#define MOD_INFO_DEP     0x01 /* dependency module, its data cannot be changed, but are required for validation */
#define MOD_INFO_INV_DEP 0x02 /* inverse dependency module, its data cannot be changed, but will be validated */
#define MOD_INFO_REQ     0x04 /* required module, its data can be changed and it will be validated */
#define MOD_INFO_TYPE_MASK 0x07 /* just a mask for all module types */

#define MOD_INFO_LOCK    0x08 /* locked module */
#define MOD_INFO_CHANGED 0x10 /* module data were changed */

struct sr_mod_info_s {
    sr_datastore_t ds;
    struct lyd_node *diff;
    int dflt_change;
    sr_conn_ctx_t *conn;

    struct sr_mod_info_mod_s {
        sr_mod_t *shm_mod;
        uint8_t state;
        const struct lys_module *ly_mod;
        struct lyd_node *mod_data;
        uint32_t event_id;

        sr_shm_t shm_sub_cache;
    } *mods;
    uint32_t mod_count;
};

sr_error_info_t *sr_modinfo_perm_check(struct sr_mod_info_s *mod_info, int wr);

sr_error_info_t *sr_modinfo_edit_diff(const struct lyd_node *edit, struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_modinfo_diff(struct sr_mod_info_s *src_mod_info, struct sr_mod_info_s *mod_info);

sr_error_info_t *sr_modinfo_validate(struct sr_mod_info_s *mod_info, int finish_diff);

sr_error_info_t *sr_modinfo_op_validate(struct sr_mod_info_s *mod_info, struct lyd_node *op, sr_mod_data_dep_t *shm_deps,
        uint16_t shm_dep_count, int output);

sr_error_info_t *sr_modinfo_data_update(struct sr_mod_info_s *mod_info, uint8_t mod_type, sr_sid_t *sid,
        sr_error_info_t **cb_error_info);

void sr_modinfo_data_replace(struct sr_mod_info_s *mod_info, uint8_t mod_type, struct lyd_node **config_p);

sr_error_info_t *sr_modinfo_get_filter(sr_session_ctx_t *session, const char *xpath, struct sr_mod_info_s *mod_info,
        struct ly_set **result);

sr_error_info_t *sr_modinfo_store(struct sr_mod_info_s *mod_info);

void sr_modinfo_free(struct sr_mod_info_s *mod_info);

#endif
