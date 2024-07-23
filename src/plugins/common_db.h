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

#endif /* _COMMON_DB_H */
