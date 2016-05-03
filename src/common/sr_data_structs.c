/**
 * @file sr_data_structs.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>
 * @brief Sysrepo data structures implementation.
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
#include "sr_data_structs.h"

#ifdef USE_AVL_LIB
#include <avl.h>
#else
#include <redblack.h>
#endif

/**
 * @brief Common context of balanced binary tree, independent of the library used.
 */
typedef struct sr_btree_s {
#ifdef USE_AVL_LIB
    avl_tree_t *avl_tree;    /**< AVL tree context. */
#else
    struct rbtree *rb_tree;  /**< Red-black tree context. */
    RBLIST *rb_list;         /**< List used to walk in the red-black tree. */
#endif
    sr_btree_compare_item_cb compare_item_cb;
    sr_btree_free_item_cb free_item_cb;
} sr_btree_t;

#ifndef USE_AVL_LIB
/**
 * @brief internal callback used only by Red-black tree.
 */
static int
sr_redblack_compare_item_cb(const void *item1, const void *item2, const void *ctx)
{
    sr_btree_t *tree = (sr_btree_t*)ctx;
    if (NULL != tree) {
        return tree->compare_item_cb(item1, item2);
    }
    return 0;
}
#endif

int
sr_btree_init(sr_btree_compare_item_cb compare_item_cb, sr_btree_free_item_cb free_item_cb, sr_btree_t **tree_p)
{
    sr_btree_t *tree = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG2(compare_item_cb, tree_p);

    tree = calloc(1, sizeof(*tree));
    CHECK_NULL_NOMEM_RETURN(tree);

    tree->compare_item_cb = compare_item_cb;
    tree->free_item_cb = free_item_cb;

#ifdef USE_AVL_LIB
    tree->avl_tree = avl_alloc_tree(compare_item_cb, free_item_cb);
    CHECK_NULL_NOMEM_GOTO(tree->avl_tree, rc, cleanup);
#else
    tree->rb_tree = rbinit(sr_redblack_compare_item_cb, tree);
    CHECK_NULL_NOMEM_GOTO(tree->rb_tree, rc, cleanup);
#endif

    *tree_p = tree;
    return SR_ERR_OK;

cleanup:
    free(tree);
    return rc;
}

void
sr_btree_cleanup(sr_btree_t* tree)
{
    if (NULL != tree) {
#ifdef USE_AVL_LIB
        /* calls free item callback on each node & destroys the tree  */
        avl_free_tree(tree->avl_tree);
#else
        /* call free item callback on each node */
        if (NULL != tree->free_item_cb) {
            RBLIST *rblist = rbopenlist(tree->rb_tree);
            if (NULL != rblist) {
                void *item = NULL;
                while((item = (void*)rbreadlist(rblist))) {
                    tree->free_item_cb(item);
                }
                rbcloselist(rblist);
            }
        }
        /* destroy the tree */
        if (NULL != tree->rb_list) {
            rbcloselist(tree->rb_list);
        }
        rbdestroy(tree->rb_tree);
#endif
        /* free our context */
        free(tree);
    }
}

int
sr_btree_insert(sr_btree_t *tree, void *item)
{
    CHECK_NULL_ARG2(tree, item);

#ifdef USE_AVL_LIB
    avl_node_t *node = avl_insert(tree->avl_tree, item);
    if (NULL == node) {
        if (EEXIST == errno) {
            return SR_ERR_DATA_EXISTS;
        } else {
            return SR_ERR_NOMEM;
        }
    }
#else
    const void *tmp_item = rbsearch(item, tree->rb_tree);
    if (NULL == tmp_item) {
        return SR_ERR_NOMEM;
    } else if(tmp_item != item) {
        return SR_ERR_DATA_EXISTS;
    }
#endif

    return SR_ERR_OK;
}

void
sr_btree_delete(sr_btree_t *tree, void *item)
{
    CHECK_NULL_ARG_VOID2(tree, item);

#ifdef USE_AVL_LIB
    avl_delete(tree->avl_tree, item);
#else
    rbdelete(item, tree->rb_tree);
    if (NULL != tree->free_item_cb) {
        tree->free_item_cb(item);
    }
#endif
}

void *
sr_btree_search(const sr_btree_t *tree, const void *item)
{
    if (NULL == tree || NULL == item) {
        return NULL;
    }

#ifdef USE_AVL_LIB
    avl_node_t *node = avl_search(tree->avl_tree, item);
    if (NULL != node) {
        return node->item;
    }
#else
    return (void*)rbfind(item, tree->rb_tree);
#endif

    return NULL;
}

void *
sr_btree_get_at(sr_btree_t *tree, size_t index)
{
    if (NULL == tree) {
        return NULL;
    }

#ifdef USE_AVL_LIB
    avl_node_t *node = avl_at(tree->avl_tree, index);
    if (NULL != node) {
        return node->item;
    }
#else
    if (0 == index) {
        if (NULL != tree->rb_list) {
            rbcloselist(tree->rb_list);
        }
        tree->rb_list = rbopenlist(tree->rb_tree);
    }
    if (NULL != tree->rb_list) {
        void *item = (void*)rbreadlist(tree->rb_list);
        if (NULL == item) {
            rbcloselist(tree->rb_list);
            tree->rb_list = NULL;
        }
        return item;
    }
#endif

    return NULL;
}


/**
 * @brief FIFO circular buffer queue context.
 */
typedef struct sr_cbuff_s {
    void *data;       /**< Data of the buffer. */
    size_t capacity;   /**< Buffer capacity in number of elements. */
    size_t elem_size;  /**< Size of one element in the buffer */
    size_t head;       /**< Index of the first element in the buffer. */
    size_t count;      /**< Number of elements stored in the buffer. */
} sr_cbuff_t;

int
sr_cbuff_init(const size_t initial_capacity, const size_t elem_size, sr_cbuff_t **buffer_p)
{
    sr_cbuff_t *buffer = NULL;
    int rc = SR_ERR_OK;

    CHECK_NULL_ARG(buffer_p);

    SR_LOG_DBG("Initiating circular buffer for %zu elements.", initial_capacity);

    buffer = calloc(1, sizeof(*buffer));
    CHECK_NULL_NOMEM_RETURN(buffer);

    buffer->data = calloc(initial_capacity, elem_size);
    CHECK_NULL_NOMEM_GOTO(buffer->data, rc, cleanup);

    buffer->capacity = initial_capacity;
    buffer->elem_size = elem_size;
    buffer->head = 0;
    buffer->count = 0;

    *buffer_p = buffer;
    return SR_ERR_OK;

cleanup:
    free(buffer);
    return rc;
}

void
sr_cbuff_cleanup(sr_cbuff_t *buffer)
{
    if (NULL != buffer) {
        free(buffer->data);
        free(buffer);
    }
}

int
sr_cbuff_enqueue(sr_cbuff_t *buffer, void *item)
{
    void *tmp = NULL;
    size_t pos = 0;

    CHECK_NULL_ARG2(buffer, item);

    if (buffer->count == buffer->capacity) {
        /* buffer is full - double it's size */
        SR_LOG_DBG("Enlarging circular buffer from %zu to %zu elements.", buffer->capacity, buffer->capacity * 2);

        tmp = realloc(buffer->data, (buffer->capacity * 2 * buffer->elem_size));
        CHECK_NULL_NOMEM_RETURN(tmp);
        buffer->data = tmp;

        if (0 != buffer->head) {
            /* move the the elements from before head to the end */
            SR_LOG_DBG("Moving %zu circular buffer elements from pos 0 to pos %zu.", buffer->head, buffer->capacity);
            memmove(((uint8_t*)buffer->data + (buffer->capacity * buffer->elem_size)), buffer->data, (buffer->head * buffer->elem_size));
        }
        buffer->capacity *= 2;
    }

    pos = (buffer->head + buffer->count) % buffer->capacity;

    memcpy(((uint8_t*)buffer->data + (pos * buffer->elem_size)), item, buffer->elem_size);
    buffer->count++;

    SR_LOG_DBG("Circular buffer enqueue to position=%zu, current count=%zu.", pos, buffer->count);

    return SR_ERR_OK;
}

bool
sr_cbuff_dequeue(sr_cbuff_t *buffer, void *item)
{
    if (NULL == buffer || 0 == buffer->count) {
        return false;
    }

    memcpy(item, ((uint8_t*)buffer->data + (buffer->head * buffer->elem_size)), buffer->elem_size);
    buffer->head = (buffer->head + 1) % buffer->capacity;
    buffer->count--;

    SR_LOG_DBG("Circular buffer dequeue, new buffer head=%zu, count=%zu.", buffer->head, buffer->count);

    return true;
}

size_t
sr_cbuff_items_in_queue(sr_cbuff_t *buffer)
{
    if (NULL != buffer) {
        return buffer->count;
    } else {
        return 0;
    }
}

