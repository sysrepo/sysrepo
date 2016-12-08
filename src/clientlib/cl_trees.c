/**
 * @file cl_trees.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Iterative tree loading using internal sysrepo requests.
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

#include "sr_common.h"
#include "client_library.h"
#include "sysrepo/trees.h"
#include "trees_internal.h"


sr_node_t *
sr_node_get_child(sr_session_ctx_t *session, sr_node_t *node)
{
    int rc = SR_ERR_OK;

    if (NULL != node) {
        if (NULL != node->first_child && SR_TREE_ITERATOR_T == node->first_child->type) {
            rc = sr_get_subtree_next_chunk(session, node);
            if (SR_ERR_OK != rc) {
                return NULL;
            }
        }
        return node->first_child;
    } else {
        return NULL;
    }
}

sr_node_t *
sr_node_get_next_sibling(sr_session_ctx_t *session, sr_node_t *node)
{
    int rc = SR_ERR_OK;

    if (NULL != node) {
        if (NULL != node->next && SR_TREE_ITERATOR_T == node->next->type) {
            rc = sr_get_subtree_next_chunk(session, node->parent);
            if (SR_ERR_OK != rc) {
                return NULL;
            }
        }
        return node->next;
    } else {
        return NULL;
    }
}

sr_node_t *
sr_node_get_parent(sr_session_ctx_t *session, sr_node_t *node)
{
    (void)session;
    if (NULL != node) {
        return node->parent;
    } else {
        return NULL;
    }
}
