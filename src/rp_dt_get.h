/**
 * @defgroup rp_get Data tree get helpers
 * @ingroup rp
 * @{
 * @brief Function for retrieving values from data trees.
 * @file rp_dt_get.h
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 *
 *
 * @copyright
 * Copyright 2016 Cisco Systems, Inc.
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

#ifndef RP_DT_GET_H
#define RP_DT_GET_H

#include "request_processor.h"
#include "rp_dt_lookup.h"

/**
 * @brief Retrieves all nodes matching xpath using ::rp_dt_find_nodes and copy fills sr_val_t structures.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_values(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath, bool check_enable,
        sr_val_t **values, size_t *count);

/**
 * @brief Returns the value for the specified xpath. If more than one node matching xpath,
 * SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] value
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_value(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath, bool check_enable, sr_val_t **value);

/**
 * @brief Returns the value for the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [out] value
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_value_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_val_t **value);

/**
 * @brief Returns the values for the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_values_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_val_t **values, size_t *count);

/**
 * @brief Returns the values for the specified xpath. Internally calls ::rp_dt_find_nodes_with_opts
 * to identify the matching nodes. The selection of returned values can be specified by limit and offset.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] get_items_ctx\
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] offset - return the values with index and above
 * @param [in] limit - the maximum count of values that can be returned
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_values_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, rp_dt_get_items_ctx_t *get_items_ctx, sr_mem_ctx_t *sr_mem,
        const char *xpath, size_t offset, size_t limit, sr_val_t **values, size_t *count);

/**
 * @brief Fills the values from the array of nodes. The length of the
 * values array is equal to the count of the nodes in nodes set.
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation (can be NULL).
 * @param [in] nodes
 * @param [out] values
 * @param [out] value_cnt
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_values_from_nodes(sr_mem_ctx_t *sr_mem, struct ly_set *nodes, sr_val_t **values, size_t *value_cnt);

/**
 * @brief Returns subtree with the root node at the specified xpath. If more than one node matching xpath,
 * SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] subtree
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_subtree(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath, bool check_enable, sr_node_t **subtree);

/**
 * @brief Returns subtree *chunk* with the root node at the specified xpath. If more than one node matching xpath,
 * SR_ERR_INVAL_ARG is returned.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] slice_offset
 * @param [in] slice_width
 * @param [in] child_limit
 * @param [in] depth_limit
 * @param [in] check_enable
 * @param [out] chunk
 * @param [out] chunk_id
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_subtree_chunk(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath,
    size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, bool check_enable,
    sr_node_t **chunk, char **chunk_id);

/**
 * @brief Retrieves all subtrees with root nodes matching the specified xpath.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] check_enable
 * @param [out] values
 * @param [out] count
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_subtrees(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath, bool check_enable,
        sr_node_t **subtrees, size_t *count);

/**
 * @brief Retrieves all subtree *chunks* with root nodes matching the specified xpath.
 * @param [in] dm_ctx
 * @param [in] data_tree
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] slice_offset
 * @param [in] slice_width
 * @param [in] child_limit
 * @param [in] depth_limit
 * @param [in] check_enable
 * @param [out] values
 * @param [out] count
 * @param [out] chunk_ids
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_subtrees_chunks(const dm_ctx_t *dm_ctx, struct lyd_node *data_tree, sr_mem_ctx_t *sr_mem, const char *xpath,
    size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, bool check_enable, sr_node_t **chunks,
    size_t *count, char ***chunk_ids);

/**
 * @brief Returns the subtree whose root node is referenced by the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [out] subtree
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_subtree_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath, sr_node_t **subtree);

/**
 * @brief Returns the subtree *chunk* whose root node is referenced by the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] slice_offset
 * @param [in] slice_width
 * @param [in] child_limit
 * @param [in] depth_limit
 * @param [out] subtree
 * @param [out] subtree_id
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_subtree_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
        size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, sr_node_t **subtree, char **subtree_id);

/**
 * @brief Retrieves all subtrees with root nodes matching the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [out] subtrees
 * @param [out] count
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_subtrees_wrapper(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
        sr_node_t **subtrees, size_t *count);

/**
 * @brief Retrieves all subtree *chunks* with root nodes matching the specified xpath.
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @param [in] sr_mem
 * @param [in] xpath
 * @param [in] slice_offset
 * @param [in] slice_width
 * @param [in] child_limit
 * @param [in] depth_limit
 * @param [out] subtrees
 * @param [out] count
 * @param [out] subtree_ids
 * @return Error code (SR_ERR_OK on success), SR_ERR_NOT_FOUND, SR_ERR_UNKNOWN_MODEL, SR_ERR_BAD_ELEMENT
 */
int rp_dt_get_subtrees_wrapper_with_opts(rp_ctx_t *rp_ctx, rp_session_t *rp_session, sr_mem_ctx_t *sr_mem, const char *xpath,
        size_t slice_offset, size_t slice_width, size_t child_limit, size_t depth_limit, sr_node_t **subtrees, size_t *count,
        char ***subtree_ids);

/**
 * @brief Transforms difflist to the set of changes
 * @param [in] difflist
 * @param [out] changes
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_difflist_to_changes(struct lyd_difflist *difflist, sr_list_t **changes);

/**
 * @brief Returns the changes that match the selection based on xpath, offset and limit criteria.
 * Changes are generated from difflist when the first request came.
 * @param [in] rp_ctx
 * @param [in] session
 * @param [in] c_ctx
 * @param [in] xpath
 * @param [in] offset
 * @param [in] limit
 * @param [out] matched_changes - changes matching xpath in the range selected by offset limit
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_get_changes(rp_ctx_t *rp_ctx, rp_session_t *session, dm_commit_context_t *c_ctx, const char *xpath,
            size_t offset, size_t limit, sr_list_t **matched_changes);

/**
 * @brief Removes the state data loaded into a session
 * @param [in] rp_ctx
 * @param [in] rp_session
 * @return Error code (SR_ERR_OK on success)
 */
int rp_dt_remove_loaded_state_data(rp_ctx_t *rp_ctx, rp_session_t *rp_session);

/**
 * @brief Frees state data context.
 */
void rp_dt_free_state_data_ctx_content (rp_state_data_ctx_t *state_data);

/**
 * @brief Function tests whether node is located under(in schema hierarchy) subtree node.
 * @param [in] subtree
 * @param [in] depth_limit Maximum number of subtree levels to consider.
 * @param [in] node
 * @return bool result of the test
 */
bool rp_dt_is_under_subtree(struct lys_node *subtree, size_t depth_limit, struct lys_node *node);

#endif /* RP_DT_GET_H */

/**
 * @}
 */
