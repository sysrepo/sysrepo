/**
 * @file common_db.h
 * @author Ondrej Kusnirik (Ondrej.Kusnirik@cesnet.cz)
 * @brief common routines for database plugins header
 *
 * @copyright
 * Copyright (c) 2021 - 2024 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2024 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#ifndef _COMMON_DB_H
#define _COMMON_DB_H

#include <stdint.h>
#include <sys/types.h>

#include <libyang/libyang.h>

#include "sysrepo.h"

#define ERRINFO(err, plugin_name, type, func, message) srplg_log_errinfo(err, plugin_name, NULL, type, func " failed on %d in %s [%s].", __LINE__, __FILE__, message);

#define SRPDS_DB_LIST_KEY_LEN_BYTES 2 /* databases store the length of a list key in two bytes */
#define SRPDS_DB_LIST_KEY_LEN_BITS 7 /* databases use only 7 bits in a byte to store the length of a list key */
#define SRPDS_DB_LIST_KEY_GET_LEN(first_byte, second_byte) ((uint32_t)(first_byte) << SRPDS_DB_LIST_KEY_LEN_BITS) | second_byte /* get length of a list key */

enum srpds_db_ly_types {
    SRPDS_DB_LY_NONE = 0,      /* none */
    SRPDS_DB_LY_CONTAINER,     /* container */
    SRPDS_DB_LY_LIST,          /* list */
    SRPDS_DB_LY_TERM,          /* leaf or leaf-list */
    SRPDS_DB_LY_ANY,           /* anydata or anyxml */
    SRPDS_DB_LY_LIST_UO,       /* user-ordered list */
    SRPDS_DB_LY_LEAFLIST_UO,   /* user-ordered leaf-list */
    SRPDS_DB_LY_OPAQUE,        /* opaque node */
    SRPDS_DB_LY_META,          /* metadata */
    SRPDS_DB_LY_ATTR           /* attribute */
};

/* userordered element node with order */
typedef struct srpds_db_userordered_data_s {
    struct lyd_node *ptr;
    int64_t order;
} srpds_db_userordered_data_t;

/* userordered list or leaflist with name and size */
typedef struct srpds_db_userordered_list_s {
    char *name;
    size_t size;
    srpds_db_userordered_data_t *data;
} srpds_db_userordered_list_t;

/* userordered lists and leaflists with size */
typedef struct srpds_db_userordered_lists_s {
    size_t size;
    srpds_db_userordered_list_t *lists;
} srpds_db_userordered_lists_t;

/**
 * @brief Concatenate the keys of a list instance into a single string.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node List instance.
 * @param[out] keys String containing all of the keys and their respective lengths.
 * @param[out] keys_length Length of the @p keys .
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_concat_key_values(const char *plg_name, const struct lyd_node *node, char **keys, uint32_t *keys_length);

/**
 * @brief Goes through concatenated keys and separates them.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] keys Concatenated keys and their respective lengths
 *      (length is the first two bytes and then the key).
 * @param[out] parsed Array of keys.
 * @param[out] lengths Array of key lengths.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_parse_keys(const char *plg_name, const char *keys, char ***parsed, uint32_t **lengths);

/**
 * @brief Iterates through @p path in the direction @p direction ,
 *      finds '/' and returns a pointer to the '/'.
 *
 * @param[in] path Path ending with NULL.
 * @param[in] direction Direction in which to go through @p path .
 * 1 = from start to end. -1 = from end to start.
 * @return Pointer to the first occurence of '/' in @p path .
 */
char *srpds_path_token(const char *path, int direction);

/**
 * @brief Get how deep the node is within the data tree.
 *
 * @param[in] path Path to node.
 * @return Depth of the node.
 */
uint32_t srpds_get_node_depth(const char *path);

/**
 * @brief Get path of the parent node.
 *
 * @param[in] path Path of the current node.
 */
void srpds_get_parent_path(char *path);

/**
 * @brief Change all '/' in the path for ' ', except in the predicate.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] path Path.
 * @param[out] out Allocated result with ' '.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_modif_path(const char *plg_name, const char *path, char **out);

/**
 * @brief Set default flags for nodes and its parents.
 *
 * @param[in] node Given data node.
 */
void srpds_cont_set_dflt(struct lyd_node *node);

/**
 * @brief Get path, predicate and path without the predicate of a data node.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Given data node.
 * @param[out] predicate Predicate of the data node.
 * @param[out] standard Path of the data node. Should be freed.
 * @param[out] no_predicate Path without the predicate of the data node. Should be freed.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_predicate(const char *plg_name, const struct lyd_node *node, const char **predicate, char **standard, char **no_predicate);

/**
 * @brief Get the name of the current process user.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] uid Process user ID.
 * @param[out] username Username.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_uid2usr(const char *plg_name, uid_t uid, char **username);

/**
 * @brief Get the name of the current process group.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] gid Process group ID.
 * @param[out] group Groupname.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_gid2grp(const char *plg_name, gid_t gid, char **group);

/**
 * @brief Get the escaped string for a MongoDB query.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] string String to escape.
 * @param[out] escaped_string Escaped string.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_escape_string(const char *plg_name, const char *string, char **escaped_string);

/**
 * @brief Compare function for qsort comparing elements of userordered lists and leaflists.
 *
 * @param[in] a First element of userordered list or leaflist.
 * @param[in] b Second element of userordered list or leaflist.
 * @return >1 if @p a is after @p b or <1 if @p a is before @p b .
 */
int srpds_uo_elem_comp(const void *a, const void *b);

/**
 * @brief Add @p new_node to @p uo_lists .
 *
 * @param[in] plg_name Plugin name.
 * @param[in] new_node New node to add to @p uo_lists .
 * @param[in] order Order of the node in the uo_list.
 * @param[in] path_no_pred Path to the node without predicate (path to userordered list/leaflist).
 * @param[in,out] uo_lists Structure containing userordered lists and leaflists.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_add_uo_lists(const char *plg_name, struct lyd_node *new_node, int64_t order,
        const char *path_no_pred, srpds_db_userordered_lists_t *uo_lists);

/**
 * @brief Order all userordered lists and leaflists in @p uo_lists .
 *
 * @param[in] plg_name Plugin name.
 * @param[in,out] uo_lists Structure containing userordered lists and leaflists.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_order_uo_lists(const char *plg_name, const srpds_db_userordered_lists_t *uo_lists);

/**
 * @brief Cleanup the structure containing userordered lists and leaflists.
 *
 * @param[in] uo_lists Structure containing userordered lists and leaflists.
 */
void srpds_cleanup_uo_lists(srpds_db_userordered_lists_t *uo_lists);

/**
 * @brief Add a new node to the data tree in conventional datastore.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] ds Datastore the data tree is in.
 * @param[in] path Path to node.
 * @param[in] name Name of the node.
 * @param[in] type Type of the node.
 * @param[in] node_module Module of the node.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (XML=0 or JSON=1).
 * @param[in,out] dflt_flag Whether the node has default value.
 * @param[in] keys Array of the keys of the node (list instance).
 * @param[in] lengths Array of the lengths of the @p keys .
 * @param[in] order Order of the node in the userordered list or leaflist.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in,out] uo_lists Structure containing userordered lists and leaflists.
 * @param[in,out] parent_nodes Potential parent nodes of the new node.
 * @param[in,out] pnodes_size Size of the @p parent_nodes .
 * @param[in,out] mod_data Data tree to insert the new node into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_add_conv_mod_data(const char *plg_name, sr_datastore_t ds, const char *path, const char *name,
        enum srpds_db_ly_types type, struct lys_module *node_module, const char *value, int32_t valtype, int *dflt_flag,
        const char **keys, uint32_t *lengths, int64_t order, const char *path_no_pred,
        srpds_db_userordered_lists_t *uo_lists, struct lyd_node ***parent_nodes, size_t *pnodes_size,
        struct lyd_node **mod_data);

/**
 * @brief Add a new node to the data tree in operational datastore.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] ctx Context of the new node.
 * @param[in] path Path to node.
 * @param[in] name Name of the node.
 * @param[in] type Type of the node.
 * @param[in] module_name Name of the node's module.
 * @param[in] node_module Module of the node.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (XML=0 or JSON=1).
 * @param[in,out] dflt_flag Whether the node has default value.
 * @param[in] keys Array of the keys of the node (list instance).
 * @param[in] lengths Array of the lengths of the @p keys .
 * @param[in,out] parent_nodes Potential parent nodes of the new node.
 * @param[in,out] pnodes_size Size of the @p parent_nodes .
 * @param[in,out] mod_data Data tree to insert the new node into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_add_oper_mod_data(const char *plg_name, struct ly_ctx *ctx, const char *path, const char *name,
        enum srpds_db_ly_types type, const char *module_name, struct lys_module *node_module, const char *value,
        int32_t valtype, int *dflt_flag, const char **keys, uint32_t *lengths, struct lyd_node ***parent_nodes,
        size_t *pnodes_size, struct lyd_node **mod_data);

/**
 * @brief Get all the values associated with the node.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Data node for which to get the values.
 * @param[out] value Value of the node.
 * @param[out] prev Value of the node before this node.
 * @param[out] orig_prev Original value of the node before this node.
 * @param[out] prev_pred Value of the node before this node in predicate.
 * @param[out] orig_prev_pred Original value of the node before this node in predicate.
 * @param[out] any_value Value of the type 'any value'.
 * @param[out] valtype Type of the node's value (XML or JSON).
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_values(const char *plg_name, struct lyd_node *node, const char **value, const char **prev,
        const char **orig_prev, char **prev_pred, char **orig_prev_pred, char **any_value, int32_t *valtype);

/**
 * @brief Free all the memory allocated in srpds_get_values().
 *
 * @param[in] node Data node for which to free the values.
 * @param[in] prev Value of the node before this node.
 * @param[in] orig_prev Original value of the node before this node.
 * @param[in,out] prev_pred Value of the node before this node in predicate.
 * @param[in,out] orig_prev_pred Original value of the node before this node in predicate.
 * @param[in,out] any_value Value of the type 'any value'.
 */
void srpds_cleanup_values(struct lyd_node *node, const char *prev, const char *orig_prev, char **prev_pred,
        char **orig_prev_pred, char **any_value);

#endif /* _COMMON_DB_H */
