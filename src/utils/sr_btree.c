/**
 * @file sr_btree.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo balanced binary tree implementation.
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

#include <avl.h>

#include "sr_common.h"
#include "sr_btree.h"

typedef struct sr_btree_s {
    avl_tree_t avl_tree;
    sr_btree_compare_cb compare_cb;
    sr_btree_freeitem_cb freeitem_cb;
} sr_btree_t;

int
sr_btree_init(sr_btree_compare_cb compare_cb, sr_btree_freeitem_cb freeitem_cb, sr_btree_t **tree_p)
{
    sr_btree_t *tree = NULL;

    CHECK_NULL_ARG3(compare_cb, freeitem_cb, tree_p);

    tree = calloc(1, sizeof(*tree));
    if (NULL == tree) {
        return SR_ERR_NOMEM;
    }
    tree->compare_cb = compare_cb;
    tree->freeitem_cb = freeitem_cb;

    avl_init_tree(&tree->avl_tree, compare_cb, freeitem_cb);

    *tree_p = tree;
    return SR_ERR_OK;
}

void
sr_btree_cleanup(sr_btree_t* tree)
{
    if (NULL != tree) {
        avl_free_tree(&tree->avl_tree);
    }
}

int
sr_btree_insert(sr_btree_t *tree, void *item)
{
    CHECK_NULL_ARG2(tree, item);

    avl_node_t *node = avl_insert(&tree->avl_tree, item);
    if (NULL == node) {
        return SR_ERR_INTERNAL;
    }

    return SR_ERR_OK;
}

void
sr_btree_delete(sr_btree_t *tree, const void *item)
{
    CHECK_NULL_ARG_VOID2(tree, item);

    avl_delete(&tree->avl_tree, item);
}

void *
sr_btree_search(const sr_btree_t *tree, const void *item)
{
    if (NULL == tree || NULL == item) {
        return NULL;
    }

    avl_node_t *node = avl_search(&tree->avl_tree, item);
    if (NULL != node) {
        return node->item;
    }

    return NULL;
}

void *
sr_btree_get_at(const sr_btree_t *tree, unsigned int index)
{
    if (NULL == tree) {
        return NULL;
    }

    avl_node_t *node = avl_at(&tree->avl_tree, index);
    if (NULL != node) {
        return node->item;
    }

    return NULL;
}
