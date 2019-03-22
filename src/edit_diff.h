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

/**
 * @brief Set an operation (attribute) for an edit node.
 *
 * @param[in] edit Node to modify.
 * @param[in] op Operation to set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_set_oper(struct lyd_node *edit, const char *op);

/**
 * @brief Delete an attribute from an edit node. Only internal (from ietf-netconf or sysrepo modules)
 * ones are considered.
 *
 * @param[in] edit Node to modify.
 * @param[in] name Name of the attribute.
 */
void sr_edit_del_attr(struct lyd_node *edit, const char *name);

/**
 * @brief Apply sysrepo edit on a specific module data tree.
 *
 * @param[in] edit Edit tree to apply.
 * @param[in] ly_mod Data tree module.
 * @param[in,out] data Data tree to modify.
 * @param[out] mod_diff Optionally create the actual diff of the original data tree and the new one.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **mod_diff);

/**
 * @brief Apply sysrepo diff on a specific module data tree.
 *
 * @param[in] diff Diff tree to apply.
 * @param[in] ly_mod Data tree module.
 * @param[in,out] data Data tree to modify.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_mod_apply(const struct lyd_node *diff, const struct lys_module *ly_mod, struct lyd_node **data);

/**
 * @brief Merge validation libyang diff into sysrepo diff.
 *
 * @param[in,out] diff Existing sysrepo diff.
 * @param[in] ly_ctx libyang context.
 * @param[in] ly_diff libyang validation diff.
 * @param[out] dflt_change Whether any value default flag changed.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_val_diff_merge(struct lyd_node **diff, struct ly_ctx *ly_ctx, struct lyd_difflist *ly_diff,
        int *dflt_change);

/**
 * @brief Transform libyang diff into sysrepo diff.
 *
 * @param[in] ly_diff libyang diff.
 * @param[out] diff_p sysrepo diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_ly2sr(struct lyd_difflist *ly_diff, struct lyd_node **diff_p);

/**
 * @brief Add change into sysrepo edit.
 *
 * @param[in] session Session to use.
 * @param[in] xpath XPath of the change node.
 * @param[in] value Value of the change node.
 * @param[in] operation Operation of the change node.
 * @param[in] def_operation Default operation of the change.
 * @param[in] position Optional position of the change node.
 * @param[in] keys Optional relative list instance keys predicate for move change.
 * @param[in] val Optional relative leaf-list value for move change.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val);

/**
 * @brief Get next change from a sysrepo diff set.
 *
 * @param[in] set Set with nodes from a sysrepo diff.
 * @param[in,out] idx Index of the next change.
 * @param[out] node Changed node.
 * @param[out] op Change operation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_set_getnext(struct ly_set *set, uint32_t *idx, struct lyd_node **node, sr_change_oper_t *op);

#endif
