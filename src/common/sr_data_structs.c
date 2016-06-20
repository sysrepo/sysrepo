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
#include <fcntl.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/stat.h>


#ifdef USE_AVL_LIB
#include <avl.h>
#else
#include <redblack.h>
#endif

#define SR_LIST_INIT_SIZE 4  /**< Initial size of the sysrepo list (in number of elements). */

int
sr_llist_init(sr_llist_t **llist_p)
{
    sr_llist_t *llist = NULL;

    llist = calloc(1, sizeof(*llist));
    CHECK_NULL_NOMEM_RETURN(llist);

    *llist_p = llist;
    return SR_ERR_OK;
}

void
sr_llist_cleanup(sr_llist_t *llist)
{
    sr_llist_node_t *node = NULL, *tmp = NULL;

    if (NULL != llist) {
        node = llist->first;
        while (NULL != node) {
            tmp = node;
            node = node->next;
            free(tmp);
        }
        free(llist);
    }
}

int
sr_llist_add_new(sr_llist_t *llist, void *data)
{
    sr_llist_node_t *node = NULL;

    CHECK_NULL_ARG2(llist, data);

    node = calloc(1, sizeof(*node));
    CHECK_NULL_NOMEM_RETURN(node);

    node->data = data;

    if (NULL != llist->last) {
        llist->last->next = node;
        node->prev = llist->last;
    }
    llist->last = node;

    if (NULL == llist->first) {
        llist->first = node;
    }

    return SR_ERR_OK;
}

int
sr_llist_rm(sr_llist_t *llist, sr_llist_node_t *node)
{
    CHECK_NULL_ARG2(llist, node);

    if (NULL != node->prev) {
        node->prev->next = node->next;
    }
    if (NULL != node->next) {
        node->next->prev = node->prev;
    }
    if (node == llist->last) {
        llist->last = node->prev;
    }
    if (node == llist->first) {
        llist->first = node->next;
    }
    free(node);

    return SR_ERR_OK;
}

int
sr_list_init(sr_list_t **list)
{
    CHECK_NULL_ARG(list);

    *list = calloc(1, sizeof(**list));
    CHECK_NULL_NOMEM_RETURN(*list);

    return SR_ERR_OK;
}

void
sr_list_cleanup(sr_list_t *list)
{
    if (NULL != list) {
        free(list->data);
        free(list);
    }
}

int
sr_list_add(sr_list_t *list, void *item)
{
    void **tmp = NULL;

    CHECK_NULL_ARG2(list, item);

    if (0 == list->_size) {
        /* allocate initial space */
        list->data = calloc(SR_LIST_INIT_SIZE, sizeof(*list->data));
        CHECK_NULL_NOMEM_RETURN(list->data);
        list->_size = SR_LIST_INIT_SIZE;
    } else if (list->_size == list->count) {
        /* enlarge the space */
        tmp = realloc(list->data,  (list->_size << 1) * sizeof(*list->data));
        CHECK_NULL_NOMEM_RETURN(tmp);
        list->data = tmp;
        list->_size <<= 1;
    }

    list->data[list->count] = item;
    list->count++;

    return SR_ERR_OK;
}

int
sr_list_rm(sr_list_t *list, void *item)
{
    CHECK_NULL_ARG2(list, item);

    if (item == list->data[list->count - 1]) {
        /* just "remove" the last item */
        list->count--;
        return SR_ERR_OK;
    }

    for (size_t i = 0; i < (list->count - 1); i++) {
        /* find and remove matching item */
        if (item == list->data[i]) {
            return sr_list_rm_at(list, i);
        }
    }

    return SR_ERR_NOT_FOUND;
}

int
sr_list_rm_at(sr_list_t *list, size_t index)
{
    CHECK_NULL_ARG(list);

    if (index > list->count - 1) {
        SR_LOG_ERR("Index %zu out of bounds of the list (0 - %zu)", index, list->count - 1);
        return SR_ERR_INVAL_ARG;
    }

    if (index == (list->count - 1)) {
        /* just "remove" the last item */
        list->count--;
    } else {
        /* move the remaining items forward */
        memmove(&list->data[index], &list->data[index + 1], (list->count - index - 1) * sizeof(*list->data));
        list->count--;
    }

    return SR_ERR_OK;
}

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

/**
 * @brief Holds binary tree with filename -> fd maping. This structure
 * is used to check file locks inside of the process and to avoid
 * the loss of the lock by file closing. File name  is first looked
 * up in this structure to detect if the file is currently opened by the process.
 * File can be closed and unlocked by fd.
 */
typedef struct sr_locking_set_s {
    sr_btree_t *lock_files;       /**< Binary tree of lock files for fast look up by file name */
    sr_btree_t *fd_index;         /**< Binary tree for fast lookup by fd, only index to the items stored in lock_files binary tree */
    pthread_mutex_t mutex;        /**< Mutex for exclusive access to binary tree */
    pthread_cond_t cond;          /**< Condition variable used for blocking lock */
} sr_locking_set_t;

/**
 * @brief The item of the lock_files binary tree in dm_lock_ctx_t
 */
typedef struct sr_lock_item_s {
    char *filename;               /**< File name of the lockfile */
    int fd;                       /**< File descriptor of the file */
    bool locked;                  /**< Flag signalizing that file is locked */
} sr_lock_item_t;

/**
 * @brief Compare two lock items by filename
 */
static int
sr_compare_lock_item(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sr_lock_item_t *item_a = (sr_lock_item_t *) a;
    sr_lock_item_t *item_b = (sr_lock_item_t *) b;

    int res = strcmp(item_a->filename, item_b->filename);
    if (res == 0) {
        return 0;
    } else if (res < 0) {
        return -1;
    } else {
        return 1;
    }

}

/**
 * @brief Compare two lock items by fd
 */
static int
sr_compare_lock_item_fd(const void *a, const void *b)
{
    assert(a);
    assert(b);
    sr_lock_item_t *item_a = (sr_lock_item_t *) a;
    sr_lock_item_t *item_b = (sr_lock_item_t *) b;


    if (item_a->fd == item_b->fd) {
        return 0;
    } else if (item_a->fd < item_b->fd) {
        return -1;
    } else {
        return 1;
    }

}

static void
sr_free_lock_item(void *lock_item)
{
    CHECK_NULL_ARG_VOID(lock_item);
    sr_lock_item_t *li = (sr_lock_item_t *) lock_item;
    free(li->filename);
    if (-1 != li->fd) {
        SR_LOG_DBG("Closing fd = %d", li->fd);
        close(li->fd);
    }
    free(li);
}

int
sr_locking_set_init(sr_locking_set_t **lset_p){
    CHECK_NULL_ARG(lset_p);
    int rc = SR_ERR_OK;
    sr_locking_set_t *lset = NULL;

    lset = calloc(1, sizeof(*lset));
    CHECK_NULL_NOMEM_RETURN(lset);

    pthread_mutex_init(&lset->mutex, NULL);
    pthread_cond_init(&lset->cond, NULL);
    rc = sr_btree_init(sr_compare_lock_item, sr_free_lock_item, &lset->lock_files);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of lock files binary tree failed");

    rc = sr_btree_init(sr_compare_lock_item_fd, NULL, &lset->fd_index);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Creating of lock files binary tree failed");

    *lset_p = lset;
    return rc;

cleanup:
    sr_locking_set_cleanup(lset);
    return rc;
}

void
sr_locking_set_cleanup(sr_locking_set_t *lset)
{
    if (NULL != lset) {
        sr_btree_cleanup(lset->fd_index);
        sr_btree_cleanup(lset->lock_files);
        pthread_mutex_destroy(&lset->mutex);
        pthread_cond_destroy(&lset->cond);
        free(lset);
    }
}

int
sr_locking_set_lock_file_open(sr_locking_set_t *lock_ctx, char *filename, bool write, bool blocking, int *fd)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    int rc = SR_ERR_OK;
    sr_lock_item_t lookup_item = {0,};
    sr_lock_item_t *found_item = NULL;
    lookup_item.filename = filename;

    MUTEX_LOCK_TIMED_CHECK_RETURN(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->lock_files, &lookup_item);
    if (NULL == found_item) {
        found_item = calloc(1, sizeof(*found_item));
        CHECK_NULL_NOMEM_GOTO(found_item, rc, cleanup);

        found_item->fd = -1;
        found_item->filename = strdup(filename);
        found_item->locked = false;
        if (NULL == found_item->filename) {
            SR_LOG_ERR_MSG("Filename duplication failed");
            free(found_item);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        rc = sr_btree_insert(lock_ctx->lock_files, found_item);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Adding to binary tree failed");
            sr_free_lock_item(found_item);
            goto cleanup;
        }

    }

    if (!blocking && found_item->locked) {
        rc = SR_ERR_LOCKED;
        SR_LOG_INF("File %s locked by other process", filename);
        goto cleanup;
    }

    while (found_item->locked) {
        pthread_cond_wait(&lock_ctx->cond, &lock_ctx->mutex);
    }

    if (-1 == found_item->fd) {
        found_item->fd = open(filename, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH | S_IWOTH);
        if (-1 == found_item->fd) {
            if (EACCES == errno) {
                SR_LOG_ERR("Insufficient permissions to lock the file '%s'", filename);
                rc = SR_ERR_UNAUTHORIZED;
            } else {
                SR_LOG_ERR("Error by opening the file '%s': %s", filename, sr_strerror_safe(errno));
                rc = SR_ERR_INTERNAL;
            }
            goto cleanup;
        }
    }

    rc = sr_lock_fd(found_item->fd, write, blocking);
    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("File %s has been locked", filename);
        found_item->locked = true;
        rc = sr_btree_insert(lock_ctx->fd_index, found_item);
        CHECK_RC_LOG_GOTO(rc, cleanup, "Insert into fd index failed file %s (fd = %d)", found_item->filename, found_item->fd);
    } else {
        SR_LOG_WRN("File %s can not be locked", filename);
        close(found_item->fd);
        found_item->fd = -1;
    }

    if (NULL != fd) {
        *fd = found_item->fd;
    }

cleanup:
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
}

int
sr_locking_set_lock_fd(sr_locking_set_t *lock_ctx, int fd, char *filename, bool write, bool blocking)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    int rc = SR_ERR_OK;
    sr_lock_item_t lookup_item = {0,};
    sr_lock_item_t *found_item = NULL;
    lookup_item.filename = filename;

    MUTEX_LOCK_TIMED_CHECK_RETURN(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->lock_files, &lookup_item);
    if (NULL == found_item) {
        found_item = calloc(1, sizeof(*found_item));
        CHECK_NULL_NOMEM_GOTO(found_item, rc, cleanup);

        found_item->fd = -1;
        found_item->filename = strdup(filename);
        if (NULL == found_item->filename) {
            SR_LOG_ERR_MSG("Filename duplication failed");
            free(found_item);
            rc = SR_ERR_INTERNAL;
            goto cleanup;
        }

        rc = sr_btree_insert(lock_ctx->lock_files, found_item);
        if (SR_ERR_OK != rc) {
            SR_LOG_ERR_MSG("Adding to binary tree failed");
            sr_free_lock_item(found_item);
            goto cleanup;
        }
    }

    if (!blocking && found_item->locked) {
        rc = SR_ERR_LOCKED;
        SR_LOG_INF("File %s can not be locked", filename);
        goto cleanup;
    }

    while (found_item->locked) {
        pthread_cond_wait(&lock_ctx->cond, &lock_ctx->mutex);
    }

    rc = sr_lock_fd(fd, write, blocking);
    if (SR_ERR_OK == rc) {
        SR_LOG_DBG("File %s has been locked", filename);
        found_item->fd = fd;
        found_item->locked = true;

        rc = sr_btree_insert(lock_ctx->fd_index, found_item);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Insert into fd index failed");
    } else {
        SR_LOG_WRN("File %s can not be locked", filename);
        found_item->fd = -1;
    }


cleanup:
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
}

int
sr_locking_set_unlock_close_file(sr_locking_set_t* lock_ctx, char* filename)
{
    CHECK_NULL_ARG2(lock_ctx, filename);
    int rc = SR_ERR_OK;
    sr_lock_item_t lookup_item = {0,};
    sr_lock_item_t *found_item = NULL;
    lookup_item.filename = filename;

    MUTEX_LOCK_TIMED_CHECK_RETURN(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->lock_files, &lookup_item);
    if (NULL == found_item || -1 == found_item->fd) {
        SR_LOG_ERR("File %s has not been locked in this context", filename);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    sr_btree_delete(lock_ctx->fd_index, found_item);
    sr_unlock_fd(found_item->fd);

    rc = close(found_item->fd);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Close failed %s", sr_strerror_safe(errno));
    }
    found_item->locked = false;
    found_item->fd = -1;
    SR_LOG_DBG("File %s has been unlocked", filename);

cleanup:
    pthread_cond_broadcast(&lock_ctx->cond);
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
}

int
sr_locking_set_unlock_close_fd(sr_locking_set_t* lock_ctx, int fd)
{
    CHECK_NULL_ARG(lock_ctx);
    int rc = SR_ERR_OK;
    sr_lock_item_t lookup_item = {0,};
    sr_lock_item_t *found_item = NULL;
    lookup_item.fd = fd;

    MUTEX_LOCK_TIMED_CHECK_RETURN(&lock_ctx->mutex);

    found_item = sr_btree_search(lock_ctx->fd_index, &lookup_item);
    if (NULL == found_item || -1 == found_item->fd) {
        SR_LOG_ERR("File %s has not been locked in this context fd (%d)", NULL != found_item ? found_item->filename : "", fd);
        rc = SR_ERR_INVAL_ARG;
        goto cleanup;
    }
    sr_unlock_fd(found_item->fd);
    SR_LOG_DBG("File %s (fd = %d) has been unlocked", found_item->filename, fd);

    rc = close(found_item->fd);
    if (SR_ERR_OK != rc) {
        SR_LOG_WRN("Close failed %s", sr_strerror_safe(errno));
    }

    /* remove from index tree */
    sr_btree_delete(lock_ctx->fd_index, found_item);
    found_item->locked = false;
    found_item->fd = -1;

cleanup:
    pthread_cond_broadcast(&lock_ctx->cond);
    pthread_mutex_unlock(&lock_ctx->mutex);
    return rc;
}
