/**
 * @file common_db.h
 * @author Ondrej Kusnirik (Ondrej.Kusnirik@cesnet.cz)
 * @brief common routines for database plugins header
 *
 * @copyright
 * Copyright (c) 2021 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2025 CESNET, z.s.p.o.
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

#define ERRINFO(err, plugin_name, type, func, message) \
        srplg_log_errinfo(err, plugin_name, NULL, type, func " failed on %d in %s [%s].", __LINE__, __FILE__, message)

#define SRPDS_DB_LIST_KEY_LEN_BYTES 2 /* databases store the length of a list key in two bytes */
#define SRPDS_DB_LIST_KEY_LEN_BITS 7 /* databases use only 7 bits in a byte to store the length of a list key */
#define SRPDS_DB_LIST_KEY_GET_LEN(first_byte, second_byte) \
        ((uint32_t)(first_byte) << SRPDS_DB_LIST_KEY_LEN_BITS) | second_byte /* get length of a list key */
#define SRPDS_DB_UO_ELEMS_GAP_SIZE 1024 /* initial gap between elements in user-ordered lists and leaf-lists */

enum srpds_db_ly_types {
    SRPDS_DB_LY_NONE = 0,      /* none */
    SRPDS_DB_LY_CONTAINER,     /* container */
    SRPDS_DB_LY_LIST,          /* list */
    SRPDS_DB_LY_TERM,          /* leaf or leaf-list */
    SRPDS_DB_LY_ANY,           /* anydata or anyxml */
    SRPDS_DB_LY_LIST_UO,       /* user-ordered list */
    SRPDS_DB_LY_LEAFLIST_UO,   /* user-ordered leaf-list */
    SRPDS_DB_LY_OPAQUE         /* opaque node */
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
sr_error_info_t *srpds_concat_key_values(const char *plg_name, const struct lyd_node *node, char **keys,
        uint32_t *keys_length);

/**
 * @brief Goes through concatenated keys and separates them.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] keys Concatenated keys and their respective lengths
 *      (length is the first two bytes and then the key).
 * @param[out] parsed Array of keys.
 * @param[out] bit_lengths Array of key lengths in bits.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_parse_keys(const char *plg_name, const char *keys, char ***parsed, uint32_t **bit_lengths);

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
 * @brief Get predicate of a data node.
 *
 * @param[in] path Path of the data node.
 * @param[in] path_no_pred Path without the predicate of the data node.
 * @return Predicate.
 */
const char *srpds_get_predicate(const char *path, const char *path_no_pred);

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
 * @param[in] escape_character Character to escape with ('\' or '%'). '%' is used to escape in Lua.
 * @param[out] escaped_string Escaped string.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_escape_string(const char *plg_name, const char *string, char escape_character,
        char **escaped_string);

/**
 * @brief Find the node @p node from one tree in another tree @p tree and store it in @p match .
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Node to find.
 * @param[in] tree Data tree to search.
 * @param[out] match Found node. NULL in case it was not found.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_find_node(const char *plg_name, const struct lyd_node *node, const struct lyd_node *tree,
        struct lyd_node **match);

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
 * @brief Add a new node to the data tree in the datastore.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] ly_ctx Context to use.
 * @param[in] ds Datastore the data tree is in.
 * @param[in] path Path to node.
 * @param[in] name Name of the node.
 * @param[in] type Type of the node.
 * @param[in] module_name Module name of the node.
 * @param[in] value Value of the node.
 * @param[in] valtype Type of the value (XML=0 or JSON=1).
 * @param[in,out] dflt_flag Whether the node has default value.
 * @param[in] keys Array of the keys of the node (list instance).
 * @param[in] bit_lengths Array of the lengths of the @p keys in bits.
 * @param[in] order Order of the node in the userordered list or leaflist.
 * @param[in] path_no_pred Path to the node without predicate.
 * @param[in] meta_count Number of metadata stored.
 * @param[in] meta_names Names of metadata.
 * @param[in] meta_values Values of metadata.
 * @param[in,out] uo_lists Structure containing userordered lists and leaflists.
 * @param[in,out] parent_nodes Potential parent nodes of the new node.
 * @param[in,out] pnodes_size Size of the @p parent_nodes .
 * @param[in,out] mod_data Data tree to insert the new node into.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_add_mod_data(const char *plg_name, const struct ly_ctx *ly_ctx, sr_datastore_t ds,
        const char *path, const char *name, enum srpds_db_ly_types type, const char *module_name, const char *value,
        int32_t valtype, int *dflt_flag, const char **keys, uint32_t *bit_lengths, int64_t order, const char *path_no_pred,
        int32_t meta_count, const char *meta_name, const char *meta_value, srpds_db_userordered_lists_t *uo_lists,
        struct lyd_node ***parent_nodes, size_t *pnodes_size, struct lyd_node **mod_data);

/**
 * @brief Get standard values (value and any value).
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Node to read.
 * @param[out] value Value.
 * @param[out] any_value Any value.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_norm_values(const char *plg_name, const struct lyd_node *node, const char **value,
        char **any_value);

/**
 * @brief Get key or value of the previous element in a list or a leaflist.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Node to read.
 * @param[out] prev Allocated previous key/value.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_prev_value(const char *plg_name, const struct lyd_node *node, char **prev);

/**
 * @brief Get key or value of the original previous element in a list or a leaflist.
 *
 * @param[in] plg_name Plugin name.
 * @param[in] node Node to read.
 * @param[out] orig_prev Allocated original previous key/value.
 * @return NULL on success;
 * @return Sysrepo error info on error.
 */
sr_error_info_t *srpds_get_orig_prev_value(const char *plg_name, const struct lyd_node *node, char **orig_prev);

/**
 * @brief Get count of external metadata (origin).
 *
 * @param[in] meta Metadata to traverse.
 * @return Number of external metadata.
 */
int32_t srpds_get_meta_count(const struct lyd_meta *meta);

#endif /* _COMMON_DB_H */
