/**
 * @file ly_wrap.h
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief libyang function wrappers header
 *
 * @copyright
 * Copyright (c) 2024 Deutsche Telekom AG.
 * Copyright (c) 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _LY_WRAP_H
#define _LY_WRAP_H

#define _GNU_SOURCE

#include <stdint.h>

#include <libyang/libyang.h>

#include "sysrepo_types.h"

/**
 * @brief Create a new libyang context.
 *
 * @param[in] conn Connection to read opts from and use for the LY ext data callback.
 * @param[out] ly_ctx libyang context.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_ctx_init(sr_conn_ctx_t *conn, struct ly_ctx **ly_ctx);

/**
 * @brief Parse a YANG module.
 *
 * @param[in] ctx Context to use.
 * @param[in] data Schema module data.
 * @param[in] path Schema module path.
 * @param[in] format Module format.
 * @param[in] features Array of enabled features.
 * @param[out] ly_mod Parsed module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_parse(struct ly_ctx *ctx, const char *data, const char *path, LYS_INFORMAT format,
        const char **features, struct lys_module **ly_mod);

/**
 * @brief Print a YANG module or submodule.
 *
 * @param[in] path Path of the printed module.
 * @param[in] mod Module to print.
 * @param[in] submod Submodule to print.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_print(const char *path, const struct lys_module *mod, const struct lysp_submodule *submod);

/**
 * @brief Get ietf-yang-library data of a context.
 *
 * @param[in] ctx Context to use.
 * @param[out] data Generated data.
 * @param[in] content_id Content ID to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_ctx_get_yanglib_data(const struct ly_ctx *ctx, struct lyd_node **data, uint32_t content_id);

/**
 * @brief Load a YANG module into context.
 *
 * @param[in] ctx Context to use.
 * @param[in] name Schema module name.
 * @param[in] revision Schema module revision.
 * @param[in] features Array of enabled features.
 * @param[out] ly_mod Loaded module.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_ctx_load_module(struct ly_ctx *ctx, const char *name, const char *revision,
        const char **features, const struct lys_module **ly_mod);

/**
 * @brief Compile libyang context.
 *
 * @param[in] ctx Context to compile.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_ctx_compile(struct ly_ctx *ctx);

/**
 * @brief Find a schema node based on path.
 *
 * @param[in] ctx Context to use.
 * @param[in] path Path to find.
 * @param[out] valid Optional valid flag to set instead of an error.
 * @param[out] match Found schema node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_find_path(const struct ly_ctx *ctx, const char *path, int *valid, const struct lysc_node **match);

/**
 * @brief Evaluate XPath expression on schema.
 *
 * @param[in] ctx Context to use.
 * @param[in] xpath XPath to evaluate.
 * @param[in] options XPath schema options.
 * @param[out] valid Optional valid flag to set instead of an error.
 * @param[out] set Result set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_find_xpath(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid,
        struct ly_set **set);

/**
 * @brief Find XPath atoms of an XPath.
 *
 * @param[in] ctx Context to use.
 * @param[in] xpath XPath to atomize.
 * @param[in] options XPath schema options.
 * @param[out] valid Optional valid flag to set instead of an error.
 * @param[out] set Result set with atoms.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_find_xpath_atoms(const struct ly_ctx *ctx, const char *xpath, uint32_t options, int *valid,
        struct ly_set **set);

/**
 * @brief Find XPath atoms of an parsed XPath expression.
 *
 * @param[in] ctx_node Context node to use.
 * @param[in] cur_mod Current module.
 * @param[in] exp Parsed XPath.
 * @param[in] prefixes Used resolved prefixes.
 * @param[in] options XPath schema options.
 * @param[out] set Result set with atoms.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lys_find_expr_atoms(const struct lysc_node *ctx_node, const struct lys_module *cur_mod,
        const struct lyxp_expr *exp, struct lysc_prefix *prefixes, uint32_t options, struct ly_set **set);

/**
 * @brief Parse YANG data.
 *
 * @param[in] ctx Context to use.
 * @param[in] data Data to parse.
 * @param[in] data_path Data path to parse.
 * @param[in] format Format of @p data or @p data_path file.
 * @param[in] parse_options Parse options.
 * @param[in] validation_options Validation options.
 * @param[out] tree Parsed data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_parse_data(const struct ly_ctx *ctx, const char *data, const char *data_path,
        LYD_FORMAT format, uint32_t parse_options, uint32_t validation_options, struct lyd_node **tree);

/**
 * @brief Parse a YANG operation.
 *
 * @param[in] ctx Context to use.
 * @param[in] data Data to parse.
 * @param[in] format Format of @p data.
 * @param[in] data_type Operation data type.
 * @param[out] tree Parsed operation data tree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_parse_op(const struct ly_ctx *ctx, const char *data, LYD_FORMAT format, enum lyd_type data_type,
        struct lyd_node **tree);

/**
 * @brief Print YANG data.
 *
 * @param[in] data Data to print.
 * @param[in] format Data print format.
 * @param[in] print_options Print options.
 * @param[in] fd File descriptor to print to.
 * @param[out] str Memory printed to.
 * @param[out] len Optional length of the printed data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_print_data(const struct lyd_node *data, LYD_FORMAT format, uint32_t print_options, int fd,
        char **str, uint32_t *len);

/**
 * @brief Validate a whole data tree.
 *
 * @param[in,out] data Data to validate.
 * @param[in] ctx Context to use.
 * @param[in] options Validation options.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_validate_all(struct lyd_node **data, const struct ly_ctx *ctx, uint32_t options);

/**
 * @brief Validate data of a single module.
 *
 * @param[in,out] data Data to validate.
 * @param[in] mod Module to use.
 * @param[in] options Validate options.
 * @param[out] diff Optional generated diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_validate_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options,
        struct lyd_node **diff);

/**
 * @brief Finish validation of data of a single module.
 *
 * @param[in] data Data to validate.
 * @param[in] mod Module to use.
 * @param[in] options Validate options.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_validate_module_final(struct lyd_node *data, const struct lys_module *mod, uint32_t options);

/**
 * @brief Validate data tree of an operation.
 *
 * @param[in] op Operation to validate.
 * @param[in] oper_data Operational data needed for validation.
 * @param[in] op_type Type of operation to validate.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_validate_op(struct lyd_node *op, const struct lyd_node *oper_data, enum lyd_type op_type);

/**
 * @brief Create node(s) on the path.
 *
 * @param[in] parent Parent to connect to.
 * @param[in] ctx Context to use.
 * @param[in] path Path to create.
 * @param[in] value Value to use.
 * @param[in] options New path options.
 * @param[out] new_parent First created parent.
 * @param[out] new_node Last created node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_path(struct lyd_node *parent, const struct ly_ctx *ctx, const char *path, const char *value,
        uint32_t options, struct lyd_node **new_parent, struct lyd_node **new_node);

/**
 * @brief Create a new term node.
 *
 * @param[in] parent Node parent.
 * @param[in] mod Node module.
 * @param[in] name Node name.
 * @param[in] value Node value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_term(struct lyd_node *parent, const struct lys_module *mod, const char *name,
        const char *value);

/**
 * @brief Create a new term node.
 *
 * @param[in] parent Node parent.
 * @param[in] mod Node module.
 * @param[in] name Node name.
 * @param[in] value Node value.
 * @param[out] node Created node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_term2(struct lyd_node *parent, const struct lys_module *mod, const char *name,
        const char *value, struct lyd_node **node);

/**
 * @brief Create a new list node.
 *
 * @param[in] parent Node parent.
 * @param[in] name Node name.
 * @param[in] key_value Key value, NULL for key-less list.
 * @param[out] node Created list node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_list(struct lyd_node *parent, const char *name, const char *key_value,
        struct lyd_node **node);

/**
 * @brief Create a new inner node.
 *
 * @param[in] parent Node parent.
 * @param[in] mod Node module.
 * @param[in] name Node name.
 * @param[out] node Created node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_inner(struct lyd_node *parent, const struct lys_module *mod, const char *name,
        struct lyd_node **node);

/**
 * @brief Create a new any node.
 *
 * @param[in] parent Node parent.
 * @param[in] name Node name.
 * @param[in] value Node value, is spent.
 * @param[in] value_type Type of @p value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_any(struct lyd_node *parent, const char *name, void *value, LYD_ANYDATA_VALUETYPE value_type);

/**
 * @brief Create a new opaque node.
 *
 * @param[in] ctx Context to use.
 * @param[in] name Node name.
 * @param[in] value Node value.
 * @param[in] prefix Node prefix.
 * @param[in] module_name Node module name.
 * @param[out] node Created node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_opaq(const struct ly_ctx *ctx, const char *name, const char *value, const char *prefix,
        const char *module_name, struct lyd_node **node);

/**
 * @brief Create a new metadata.
 *
 * @param[in] parent Parent of the metadata.
 * @param[in] mod Optional module of the metadata.
 * @param[in] name Metadata name, may include module name as a prefix.
 * @param[in] value Metadata value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_meta(struct lyd_node *parent, const struct lys_module *mod, const char *name,
        const char *value);

/**
 * @brief Try to create a new metadata from an attribute.
 *
 * @param[in] ctx Context to use.
 * @param[in] parent Metadata parent.
 * @param[in] attr Attribute to parse.
 * @param[out] meta Created metadata.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_meta2(const struct ly_ctx *ctx, struct lyd_node *parent, const struct lyd_attr *attr,
        struct lyd_meta **meta);

/**
 * @brief Create a new JSON attribute.
 *
 * @param[in] parent Opaque parent of the attribute.
 * @param[in] mod_name Attribute module name.
 * @param[in] name Attribute name.
 * @param[in] value Attribute value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_attr(struct lyd_node *parent, const char *mod_name, const char *name, const char *value);

/**
 * @brief Create a new XML attribute.
 *
 * @param[in] parent Opaque parent of the attribute.
 * @param[in] mod_ns Attribute module namespace.
 * @param[in] name Attribute name.
 * @param[in] value Attribute value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_attr2(struct lyd_node *parent, const char *mod_ns, const char *name, const char *value);

/**
 * @brief Create implicit data for the whole context.
 *
 * @param[in,out] data Data to add to.
 * @param[in] ctx Context to use.
 * @param[in] options New implicit options.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_implicit_all(struct lyd_node **tree, const struct ly_ctx *ctx, uint32_t options);

/**
 * @brief Create implicit data of a module.
 *
 * @param[in,out] data Data to add to.
 * @param[in] mod Module to use.
 * @param[in] options New implicit options.
 * @param[out] diff Created data diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_implicit_module(struct lyd_node **data, const struct lys_module *mod, uint32_t options,
        struct lyd_node **diff);

/**
 * @brief Create implicit data in a data tree.
 *
 * @param[in] tree Data tree to add to.
 * @param[in] options New implicit options.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_new_implicit_tree(struct lyd_node *tree, uint32_t options);

/**
 * @brief Duplicate data node(s).
 *
 * @param[in] node Subtree to duplicate.
 * @param[in] parent Optional parent to connect to.
 * @param[in] options Dup options.
 * @param[in] siblings Whether to duplicate siblings as well or only the single subtree.
 * @param[out] dup Diplicated subtree.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_dup(const struct lyd_node *node, struct lyd_node *parent, uint32_t options, int siblings,
        struct lyd_node **dup);

/**
 * @brief Duplicate data node siblings into a specific context.
 *
 * @param[in] sibling Siblings to duplicate.
 * @param[in] trg_ctx Target context.
 * @param[in] options Dup options.
 * @param[out] dup Duplicated data.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_dup_siblings_to_ctx(const struct lyd_node *sibling, const struct ly_ctx *trg_ctx,
        uint32_t options, struct lyd_node **dup);

/**
 * @brief Safely free a subtree when there is also a pointer that may point to it.
 *
 * @param[in] tree Tree to free.
 * @param[in,out] first Pointer to the first top-level node that may actually be @p tree.
 */
void sr_lyd_free_tree_safe(struct lyd_node *tree, struct lyd_node **first);

/**
 * @brief Merge 2 data trees.
 *
 * @param[in,out] target Target data tree to merge to.
 * @param[in] source Source data tree to merge.
 * @param[in] siblings Whether to merge all the siblings.
 * @param[in] options Merge options.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_merge(struct lyd_node **target, const struct lyd_node *source, int siblings, uint32_t options);

/**
 * @brief Find the nodes selected by an XPath.
 *
 * @param[in] tree Data tree to search.
 * @param[in] xpath XPath expression in JSON format.
 * @param[out] set Result set with data nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_xpath(const struct lyd_node *tree, const char *xpath, struct ly_set **set);

/**
 * @brief Find the nodes selected by an XPath with the root being the context node.
 *
 * @param[in] tree Data tree to search.
 * @param[in] xpath XPath expression in JSON format.
 * @param[out] set Result set with data nodes.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_xpath_root(const struct lyd_node *tree, const char *xpath, struct ly_set **set);

/**
 * @brief Find the nodes selected by a path.
 *
 * @param[in] tree Data tree to search.
 * @param[in] path Path expression in JSON format.
 * @param[in] with_incomplete Whether an intermediare parent should be returned or NULL in this case.
 * @param[out] match Found node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_path(const struct lyd_node *tree, const char *path, int with_incomplete,
        struct lyd_node **match);

/**
 * @brief Find the first matching sibling.
 *
 * @param[in] sibling Sibling list to search.
 * @param[in] target Target node to find.
 * @param[out] match Found node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_sibling_first(const struct lyd_node *sibling, const struct lyd_node *target,
        struct lyd_node **match);

/**
 * @brief Find the first matching sibling.
 *
 * @param[in] sibling Sibling list to search.
 * @param[in] schema Target schema node to find.
 * @param[in] value Value to find.
 * @param[out] match Found node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_sibling_val(const struct lyd_node *sibling, const struct lysc_node *schema,
        const char *value, struct lyd_node **match);

/**
 * @brief Find next matching opaque sibling node.
 *
 * @param[in] sibling First sibling to consider.
 * @param[in] name Node name to find.
 * @param[out] match Found node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_find_sibling_opaq_next(const struct lyd_node *sibling, const char *name, struct lyd_node **match);

/**
 * @brief Insert a data node sibling.
 *
 * @param[in] sibling Sibling to insert next to.
 * @param[in] node Node to insert.
 * @param[out] first First sibling in the list.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_insert_sibling(struct lyd_node *sibling, struct lyd_node *node, struct lyd_node **first);

/**
 * @brief Insert a data node child.
 *
 * @param[in] parent Parent o insert to.
 * @param[in] child Child to insert.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_insert_child(struct lyd_node *parent, struct lyd_node *child);

/**
 * @brief Change a term node value.
 *
 * @param[in] node Node to update.
 * @param[in] value Value to use.
 * @param[in] ignore_fail Whether to ignore minor failures.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_change_term(struct lyd_node *node, const char *value, int ignore_fail);

/**
 * @brief Get string value of an any node.
 *
 * @param[in] node Any node.
 * @param[out] str String value of @p node.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_any_value_str(const struct lyd_node *node, char **str);

/**
 * @brief Copy value to an any node.
 *
 * @param[in] node Any node to modify.
 * @param[in] value Value to use.
 * @param[in] value_type Value type of @p value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_any_copy_value(struct lyd_node *node, const union lyd_any_value *value,
        LYD_ANYDATA_VALUETYPE value_type);

/**
 * @brief Get the diff of 2 data tree sibling lists.
 *
 * @param[in] target Target diff siblings.
 * @param[in] source Source diff siblings.
 * @param[in] options Diff options.
 * @param[out] diff Generated diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_siblings(const struct lyd_node *target, const struct lyd_node *source, uint32_t options,
        struct lyd_node **diff);

/**
 * @brief Apply diff of a specific module on data.
 *
 * @param[in,out] data Data to modify.
 * @param[in] diff Diff to apply.
 * @param[in] mod Module to use.
 * @param[in] diff_cb Diff callback to use.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_apply_module(struct lyd_node **data, const struct lyd_node *diff,
        const struct lys_module *mod, lyd_diff_cb diff_cb);

/**
 * @brief Merge diff of a specific module.
 *
 * @param[in,out] target Target diff to merge to.
 * @param[in] source Source diff to merge.
 * @param[in] mod Specific module diff to merge.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_merge_module(struct lyd_node **target, const struct lyd_node *source,
        const struct lys_module *mod);

/**
 * @brief Merge a whole diff data tree.
 *
 * @param[in,out] target Target diff to merge to.
 * @param[in] source Source diff to merge.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_merge_all(struct lyd_node **target, const struct lyd_node *source);

/**
 * @brief Merge a single diff data tree.
 *
 * @param[in,out] target_first Target diff first sibling to merge to.
 * @param[in] target_parent Target diff parent.
 * @param[in] source Source diff to merge.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_merge_tree(struct lyd_node **target_first, struct lyd_node *target_parent,
        const struct lyd_node *source);

/**
 * @brief Reverse operations in a diff tree.
 *
 * @param[in] diff Dif to reverse.
 * @param[out] rdiff Reversed diff.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyd_diff_reverse_all(const struct lyd_node *diff, struct lyd_node **rdiff);

/**
 * @brief Create a new set.
 *
 * @param[out] set Created empty set.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_set_new(struct ly_set **set);

/**
 * @brief Add an item into a set, use as list.
 *
 * @param[in] set Set to add to.
 * @param[in] item Item to add.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_set_add(struct ly_set *set, void *item);

/**
 * @brief Merge 2 sets into one.
 *
 * @param[in] target Target set to merge to.
 * @param[in] source Source set to merge.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_set_merge(struct ly_set *target, const struct ly_set *source);

/**
 * @brief Insert into hash table.
 *
 * @param[in] ht Hash table to use.
 * @param[in] val_p Pointer to the value to insert.
 * @param[in] hash Value hash.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_lyht_insert(struct ly_ht *ht, void *val_p, uint32_t hash);

/**
 * @brief Print an xpath1.0 value into string.
 *
 * @param[in] xp_val xpath1.0 value.
 * @param[out] str Printed string value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_print_xpath10_value(const struct lyd_value_xpath10 *xp_val, char **str);

/**
 * @brief Canonize an xpath1.0 value into JSON format.
 *
 * @param[in] ctx Context to use.
 * @param[in] value Value to canonize.
 * @param[in] prefixes Prefixes for the resolved value format.
 * @param[out] str Canonizes value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_canonize_xpath10_value(const struct ly_ctx *ctx, const char *value, struct lysc_prefix *prefixes,
        char **str);

/**
 * @brief Generate an error for an opaque node.
 *
 * @param[in] node Invalid opaque node to use.
 * @return err_info.
 */
sr_error_info_t *sr_lyd_parse_opaq_error(const struct lyd_node *node);

/**
 * @brief Convert timespec to a date-and-time value.
 *
 * @param[in] ts Timespec to use.
 * @param[out] str Converted string value.
 * @return err_info, NULL on success.
 */
sr_error_info_t *sr_ly_time_ts2str(const struct timespec *ts, char **str);

#endif /* _LY_WRAP_H */
