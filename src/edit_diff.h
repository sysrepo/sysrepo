/**
 * @file edit_diff.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for routines for sysrepo edit and diff data tree handling
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

#ifndef _EDIT_DIFF_H
#define _EDIT_DIFF_H

#include <libyang/libyang.h>

#include "common.h"

/**
 * @brief All edit operations.
 */
enum edit_op {
    /* internal */
    EDIT_FINISH = -1,
    EDIT_CONTINUE = 0,
    EDIT_MOVE,
    EDIT_AUTO_REMOVE,

    /* sysrepo-specific */
    EDIT_ETHER,
    EDIT_PURGE,

    /* NETCONF */
    EDIT_NONE,
    EDIT_MERGE,
    EDIT_REPLACE,
    EDIT_CREATE,
    EDIT_DELETE,
    EDIT_REMOVE
};

/**
 * @brief Set an operation (attribute) for an edit node.
 *
 * @param[in] edit Node to modify.
 * @param[in] op Operation to set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_set_oper(struct lyd_node *edit, const char *op);

/**
 * @brief Find operation of an edit node.
 *
 * @param[in] edit Edit node.
 * @param[in] recursive Whether to search recursively in parents.
 * @param[out] own_oper Whether the operation is in the node or in some of its parents.
 * @return Edit operation for the node.
 */
enum edit_op sr_edit_find_oper(const struct lyd_node *edit, int recursive, int *own_oper);

/**
 * @brief Delete an attribute from an edit node. Only internal (from ietf-netconf or sysrepo modules)
 * ones are considered.
 *
 * @param[in] edit Node to modify.
 * @param[in] name Name of the attribute.
 */
void sr_edit_del_attr(struct lyd_node *edit, const char *name);

/**
 * @brief Get (inherited) origin of a node.
 *
 * @param[in] node Node to examine.
 * @param[out] origin Found origin.
 * @param[out] origin_own Whether the found origin is owned or inherited.
 */
void sr_edit_diff_get_origin(const struct lyd_node *node, const char **origin, int *origin_own);

/**
 * @brief Set origin of a node.
 *
 * @param[in] node Node to change.
 * @param[in] origin Effective origin of the node.
 * @param[in] overwrite Whether to overwrite even an owned \p node origin.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_diff_set_origin(struct lyd_node *node, const char *origin, int overwrite);

/**
 * @brief Apply edit move operation on the whole created data subtree (only user-ordered lists are affected).
 *
 * @param[in] match_subtree Starting diff/edit node that should have "create" operation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_created_subtree_apply_move(struct lyd_node *match_subtree);

/**
 * @brief Apply sysrepo edit on a specific module data tree.
 *
 * @param[in] edit Edit tree to apply.
 * @param[in] ly_mod Data tree module.
 * @param[in,out] data Data tree to modify.
 * @param[in,out] diff Optionally create the diff of the original data tree and the new one (or merge into diff).
 * @param[out] change Optional, set if there were some module changes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod, struct lyd_node **data,
        struct lyd_node **diff, int *change);

/**
 * @brief Merge sysrepo diff of a specific module into another diff.
 *
 * @param[in] src_diff Diff to merge.
 * @param[in] oper_conn Connection pointer of the owner of \p src_diff in case it is an operational diff.
 * Otherwise should be NULL.
 * @param[in] ly_mod Diff module.
 * @param[in,out] diff Diff to merge into.
 * @param[out] change Optional, set if there were some diff changes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_mod_merge(const struct lyd_node *src_diff, sr_conn_ctx_t *oper_conn, const struct lys_module *ly_mod,
        struct lyd_node **diff, int *change);

/**
 * @brief Apply sysrepo diff on a specific module data tree.
 *
 * @param[in] diff Diff tree to apply.
 * @param[in] ly_mod Data tree module.
 * @param[in] with_origin Whether to copy origin from diff to the data tree.
 * @param[in,out] data Data tree to modify.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_mod_apply(const struct lyd_node *diff, const struct lys_module *ly_mod, int with_origin,
        struct lyd_node **data);

/**
 * @brief Update sysrepo diff on a specific module data tree.
 * Meaning remove diff parts that cannot be applied.
 *
 * @param[in,out] diff Diff to update.
 * @param[in] ly_mod Data tree module.
 * @param[in] mod_data Data tree to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_mod_update(struct lyd_node **diff, const struct lys_module *ly_mod, const struct lyd_node *mod_data);

/**
 * @brief Merge libyang validation diff into sysrepo diff.
 *
 * @param[in,out] diff Existing sysrepo diff.
 * @param[in] type Validation diff change type.
 * @param[in] first Validation diff first item.
 * @param[in] second Validation diff second item.
 * @param[in] ly_ctx libyang context.
 * @param[out] change Set if any data change occured (it could be just dlft flag change).
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_val_diff_merge(struct lyd_node **diff, LYD_DIFFTYPE type, struct lyd_node *first,
        struct lyd_node *second, struct ly_ctx *ly_ctx, int *change);

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
 * @param[in] origin Origin of the value, used only for ::SR_DS_OPERATIONAL.
 * @param[in] isolate Whether to create the new operation separately (isolated) from the others.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_add(sr_session_ctx_t *session, const char *xpath, const char *value, const char *operation,
        const char *def_operation, const sr_move_position_t *position, const char *keys, const char *val,
        const char *origin, int isolate);

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

/**
 * @brief Reverse diff changes from change event for abort event.
 *
 * @param[in] diff Original diff.
 * @param[out] reverse_diff Reversed diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_reverse(const struct lyd_node *diff, struct lyd_node **reverse_diff);

/**
 * @brief Remove all stored diff nodes that belong to a connection that is being deleted.
 *
 * @param[in,out] diff Diff to remove from.
 * @param[in] cid Connection ID of the deleted connection.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_del_conn(struct lyd_node **diff, sr_cid_t cid);

#endif
