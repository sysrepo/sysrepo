/**
 * @file edit_diff.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for routines for sysrepo edit and diff data tree handling
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
#ifndef _EDIT_DIFF_H
#define _EDIT_DIFF_H

#include <libyang/libyang.h>

#include "common.h"

sr_error_info_t *sr_ly_edit_mod_apply(const struct lyd_node *edit, struct sr_mod_info_mod_s *mod, struct lyd_node **mod_diff);

sr_error_info_t *sr_ly_diff_mod_apply(struct lyd_node *diff, struct sr_mod_info_mod_s *mod);

sr_error_info_t *sr_ly_diff_merge(struct lyd_node **diff, struct ly_ctx *ly_ctx, struct lyd_difflist *ly_diff,
        int *dflt_change);

sr_error_info_t *sr_ly_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val);

#endif
