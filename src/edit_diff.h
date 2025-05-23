/**
 * @file edit_diff.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief header for routines for sysrepo edit and diff data tree handling
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _EDIT_DIFF_H
#define _EDIT_DIFF_H

#include <libyang/libyang.h>

#include "common_types.h"
#include "sysrepo_types.h"

/**
 * @brief All edit operations.
 */
enum edit_op {
    /* internal */
    EDIT_FINISH = -1,
    EDIT_CONTINUE = 0,
    EDIT_MOVE,
    EDIT_AUTO_REMOVE,
    EDIT_DFLT_CHANGE,

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
 * @brief Return operation from a string.
 *
 * @param[in] str Operation in string.
 * @return Operation.
 */
enum edit_op sr_edit_str2op(const char *str);

/**
 * @brief Check top-level operations in oper data and then delete them.
 *
 * @param[in] oper_data Oper data to check.
 * @param[out] op Found operation.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_oper_check_op(struct lyd_node *oper_data, enum edit_op *op);

/**
 * @brief Create/find missing parents when appending edit/diff subtree into existing edit/diff tree.
 *
 * @param[in] node Node (subtree) to append.
 * @param[in,out] tree Existing edit/diff tree, is updated.
 * @param[out] top_parent First created parent, NULL if no parents were created.
 * @param[out] node_parent Parent of @p node, may exist or be created.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_diff_create_parents(const struct lyd_node *node, struct lyd_node **tree,
        struct lyd_node **top_parent, struct lyd_node **node_parent);

/**
 * @brief Callback for libyang diff apply.
 *
 * @param[in] diff_node Diff node.
 * @param[in] data_node Matching node in data.
 * @param[in] cb_data Unused callback data.
 * @return LY_ERR value.
 */
LY_ERR sr_lyd_diff_apply_cb(const struct lyd_node *diff_node, struct lyd_node *data_node, void *cb_data);

/**
 * @brief Return string name of an operation.
 *
 * @param[in] op Operation.
 * @return String operation name.
 */
const char *sr_edit_op2str(enum edit_op op);

/**
 * @brief Set an operation (attribute) for an edit node. They are defined in sysrepo and ietf-netconf module.
 *
 * @param[in] edit Node to modify.
 * @param[in] op Operation to set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_set_oper(struct lyd_node *edit, const char *op);

/**
 * @brief Set an operation (attribute) for a diff node. They are defined in internal libyang yang module.
 *
 * @param[in] diff Node to modify.
 * @param[in] op Operation to set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_diff_set_oper(struct lyd_node *diff, const char *op);

/**
 * @brief Find operation of an edit node.
 *
 * @param[in] edit Edit node.
 * @param[in] recursive Whether to search recursively in parents.
 * @param[out] own_oper Whether the operation is in the node or in some of its parents.
 * @return Edit operation for the node.
 */
enum edit_op sr_edit_diff_find_oper(const struct lyd_node *edit, int recursive, int *own_oper);

/**
 * @brief Get (inherited) origin of a node.
 *
 * @param[in] node Node to examine.
 * @param[in] recursive Whether to search recursively in parents.
 * @param[out] origin Found origin.
 * @param[out] origin_own Whether the found origin is owned or inherited.
 */
void sr_edit_diff_get_origin(const struct lyd_node *node, int recursive, const char **origin, int *origin_own);

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
 * @param[in,out] val_err_info Validation error info to add validation errors to.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_edit_mod_apply(const struct lyd_node *edit, const struct lys_module *ly_mod,
        struct lyd_node **data, struct lyd_node **diff, int *change, sr_error_info_t **val_err_info);

/**
 * @brief Apply sysrepo operational edit on a specific module data tree.
 *
 * @param[in] tree Data tree to merge.
 * @param[in] ly_mod Data tree module.
 * @param[in,out] data Data tree to modify.
 * @param[in,out] diff Optionally create the diff of the original data and the new one (or merge into diff).
 * @param[out] change Optional, set if there were some module changes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_oper_edit_mod_apply(const struct lyd_node *tree, const struct lys_module *ly_mod,
        struct lyd_node **data, struct lyd_node **diff, int *change);

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
 * @param[in] origin Origin of the value, used only for ::SR_DS_OPERATIONAL. Must be prefixed (JSON format).
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

#endif
