/**
 * @file trees.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Functions for simplified manipulation with Sysrepo trees.
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
#include "values_internal.h"
#include "trees_internal.h"

/**
 * @brief Allocate a new instance of a sysrepo node over an existing sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context.
 * @param [in] name Name of the node to create.
 * @param [in] module_name Name of the module that this node belongs to.
 * @param [out] node_p Returned newly allocate node.
 */
int
sr_new_node(sr_mem_ctx_t *sr_mem, const char *name, const char *module_name, sr_node_t **node_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *node = NULL;

    CHECK_NULL_ARG(node_p);

    node = (sr_node_t *)sr_calloc(sr_mem, 1, sizeof *node);
    CHECK_NULL_NOMEM_RETURN(node);
    node->_sr_mem = sr_mem;

    if (name) {
        rc = sr_node_set_name(node, name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set sysrepo node name.");
    }

    if (module_name) {
        rc = sr_node_set_module(node, module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to set module name for a sysrepo node.");
    }

cleanup:
    if (SR_ERR_OK == rc) {
        *node_p = node;
    } else if (NULL == sr_mem) {
        sr_free_tree(node);
    }
    return rc;
}

/**
 * @brief Create a new sysrepo tree over a possibly existing sysrepo memory context.
 *
 * @param [in] sr_mem Sysrepo memory context to use for memory allocation.
 *                    If NULL, a new one will be created.
 * @param [in] root_name Name for the newly allocated tree root. Can be NULL.
 * @param [in] root_module_name Name of the module that defines scheme of the tree root.
 *                              Can be NULL.
 * @param [out] tree Returned newly allocated Sysrepo tree.
 */
static int
sr_new_tree_ctx(sr_mem_ctx_t *sr_mem, const char *name, const char *module_name, sr_node_t **node_p)
{
    int rc = SR_ERR_OK;
    bool new_ctx = false;

    CHECK_NULL_ARG(node_p);

    if (NULL == sr_mem) {
        rc = sr_mem_new(sizeof(sr_node_t) + (name ? strlen(name) + 1 : 0)
                                          + (module_name ? strlen(module_name) + 1 : 0),
                        &sr_mem);
        CHECK_RC_MSG_RETURN(rc, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    rc = sr_new_node(sr_mem, name, module_name, node_p);
    if (SR_ERR_OK != rc) {
        if (new_ctx) {
            sr_mem_free(sr_mem);
        }
    } else {
        if (sr_mem) {
            sr_mem->obj_count += 1;
        }
    }

    return rc;
}

int
sr_new_tree(const char *name, const char *module_name, sr_node_t **node_p)
{
    return sr_new_tree_ctx(NULL, name, module_name, node_p);
}


/**
 * @brief Create a new array of sysrepo trees.
 */
static int
sr_new_trees_ctx(sr_mem_ctx_t *sr_mem, size_t count, sr_node_t **trees_p)
{
    int rc = SR_ERR_OK;
    bool new_ctx = false;
    sr_node_t *trees = NULL;

    CHECK_NULL_ARG(trees_p);

    if (0 == count) {
        *trees_p = NULL;
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        rc = sr_mem_new((sizeof *trees) * count, &sr_mem);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to obtain new sysrepo memory.");
        new_ctx = true;
    }

    trees = (sr_node_t *)sr_calloc(sr_mem, count, sizeof *trees);
    CHECK_NULL_NOMEM_GOTO(trees, rc, cleanup);
    if (NULL != sr_mem) {
        for (size_t i = 0; i < count; ++i) {
            trees[i]._sr_mem = sr_mem;
        }
        sr_mem->obj_count += 1; /* 1 for the entire array */
    }

cleanup:
    if (SR_ERR_OK != rc) {
        if (new_ctx) {
            if (sr_mem) {
                sr_mem_free(sr_mem);
            } else {
                free(trees);
            }
        }
    } else {
        *trees_p = trees;
    }
    return SR_ERR_OK;
}

int
sr_new_trees(size_t count, sr_node_t **trees_p)
{
    return sr_new_trees_ctx(NULL, count, trees_p);
}

int
sr_node_set_name(sr_node_t *node, const char *name)
{
    CHECK_NULL_ARG2(node, name);
    return sr_mem_edit_string(node->_sr_mem, &node->name, name);
}

int
sr_node_set_module(sr_node_t *node, const char *module_name)
{
    CHECK_NULL_ARG2(node, module_name);
    return sr_mem_edit_string(node->_sr_mem, &node->module_name, module_name);
}

int
sr_node_set_string(sr_node_t *node, const char *string_val)
{
    return sr_val_set_string((sr_val_t *)node, string_val);
}

/**
 * @brief Insert child into the linked-list of children of a given parent node.
 */
void
sr_node_insert_child(sr_node_t *parent, sr_node_t *child)
{
    if (NULL == parent || NULL == child) {
        return;
    }
    if (NULL == parent->first_child) {
        parent->first_child = child;
    } else {
        parent->last_child->next = child;
    }
    if (SR_TREE_ITERATOR_T != child->type) {
        child->prev = parent->last_child;
        child->next = NULL;
        child->parent = parent;
    }
    parent->last_child = child;
}

int
sr_node_add_child(sr_node_t *parent, const char *child_name, const char *child_module_name,
        sr_node_t **child_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *child = NULL;

    CHECK_NULL_ARG2(parent, child_p);

    rc = sr_new_node(parent->_sr_mem, child_name, child_module_name, &child);

    if (SR_ERR_OK == rc) {
        sr_node_insert_child(parent, child);
        *child_p = child;
    }

    return rc;
}

/**
 * @brief Recursivelly duplicate sysrepo tree.
 */
static int
sr_dup_tree_recursive(sr_mem_ctx_t *sr_mem, sr_node_t *tree, size_t depth, sr_node_t **tree_dup_p, sr_node_t **iterator_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *tree_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG3(tree, tree_dup_p, iterator_p);

    if (0 == depth) {
        rc = sr_new_tree_ctx(sr_mem, tree->name, tree->module_name, &tree_dup);
    } else {
        rc = sr_new_node(sr_mem, tree->name, tree->module_name, &tree_dup);
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new sysrepo node.");

    rc = sr_dup_val_data((sr_val_t *)tree_dup, (sr_val_t *)tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node data.");

    if (SR_TREE_ITERATOR_T == tree_dup->type) {
        assert(NULL == *iterator_p);
        *iterator_p = tree_dup;
    } else {
        /* duplicate descendants */
        child = tree->first_child;
        while (child) {
            if (SR_TREE_ITERATOR_T == child->type && NULL != *iterator_p) {
                assert(NULL == child->next);
                sr_node_insert_child(tree_dup, *iterator_p);
            } else {
                rc = sr_dup_tree_recursive(tree_dup->_sr_mem, child, depth+1, &child_dup, iterator_p);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                sr_node_insert_child(tree_dup, child_dup);
            }
            child = child->next;
        }
    }

    *tree_dup_p = tree_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        if (NULL != sr_mem) {
            if (0 == depth) {
                sr_free_tree(tree_dup);
            }
        } else {
            sr_free_tree(tree_dup);
        }
    }

    return rc;
}

int
sr_dup_tree_ctx(sr_node_t *tree, sr_mem_ctx_t *sr_mem_dest, sr_node_t **tree_dup_p)
{
    sr_node_t *iterator = NULL;
    return sr_dup_tree_recursive(sr_mem_dest, tree, 0, tree_dup_p, &iterator);
}

int
sr_dup_tree(sr_node_t *tree, sr_node_t **tree_dup_p)
{
    return sr_dup_tree_ctx(tree, NULL, tree_dup_p);
}

int
sr_dup_trees_ctx(sr_node_t *trees, size_t count, sr_mem_ctx_t *sr_mem_dest, sr_node_t **trees_dup_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG2(trees, trees_dup_p);

    rc = sr_new_trees_ctx(sr_mem_dest, count, &trees_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new array of sysrepo nodes.");

    for (size_t i = 0; i < count; ++i) {
        sr_node_set_name(trees_dup + i, trees[i].name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node name.");
        sr_node_set_module(trees_dup + i, trees[i].module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate module of a sysrepo node.");
        rc = sr_dup_val_data((sr_val_t *)(trees_dup + i), (sr_val_t *)(trees + i));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");

        if (SR_TREE_ITERATOR_T != trees[i].type) {
            /* duplicate descendants */
            sr_node_t *iterator = NULL;
            child = trees[i].first_child;
            while (child) {
                rc = sr_dup_tree_recursive(trees_dup->_sr_mem, child, 1, &child_dup, &iterator);
                if (SR_ERR_OK != rc) {
                    goto cleanup;
                }
                sr_node_insert_child(trees_dup + i, child_dup);
                child = child->next;
            }
        }
    }

    *trees_dup_p = trees_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_trees(trees_dup, count);
    }

    return rc;
}

int
sr_dup_trees(sr_node_t *trees, size_t count, sr_node_t **trees_dup_p)
{
    return sr_dup_trees_ctx(trees, count, NULL, trees_dup_p);
}
