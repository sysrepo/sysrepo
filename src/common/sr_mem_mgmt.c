/**
 * @file sr_mem_mgmt.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo memory management implementation.
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

#include <libyang/libyang.h>
#include <assert.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>

#include "sr_mem_mgmt.h"
#include "sr_common.h"

/** Get previous item queue position */
#define QUEUE_PREV(head, len) ((head) == 0 ? ((len)-1) : ((head)-1))

/**
 * @brief A Pool of free memory contexts.
 */
typedef struct fctx_pool_s {
    sr_llist_t *fctx_llist;  /**< Free memory contexts (items are of type sr_mem_ctx_t). */
    size_t count;            /**< Number of free memory contexts. */

    size_t peak_history[MEM_PEAK_USAGE_HISTORY_LENGTH];  /**< Recent history of peak memory usage
                                                              of the contexts freed by this thread. */
    size_t peak_history_head;                            /**< Head of the peak_history queue. */

    size_t pb_peak_history[MEM_PEAK_USAGE_HISTORY_LENGTH]; /**< Piggy-backed recent history of peak memory
                                                                usage as observed by potentially different threads. */
    size_t pb_peak_history_head;                           /**< Head of the pb_peak_history queue. */
} fctx_pool_t;

static pthread_key_t fctx_key; /**< Key to the pool of free memory contexts. */
static pthread_once_t fctx_init_once = PTHREAD_ONCE_INIT; /**< For initialization of the key. */

/* Forward declaration. */
static void sr_mem_destroy(sr_mem_ctx_t *sr_mem);

/**
 * @brief Destroy pool of free contexts.
 */
static void
destroy_fctx_pool(void *fctx_pool_p)
{
    fctx_pool_t *fctx_pool = (fctx_pool_t *)fctx_pool_p;
    sr_llist_node_t *node_ll = NULL;

    if (fctx_pool) {
        node_ll = fctx_pool->fctx_llist->first;
        while (node_ll) {
            sr_mem_ctx_t *sr_mem = (sr_mem_ctx_t *)node_ll->data;
            sr_mem_destroy(sr_mem);
            node_ll = node_ll->next;
        }
        sr_llist_cleanup(fctx_pool->fctx_llist);
        free(fctx_pool);
    }
}

/**
 * @brief Initializes fctx_key.
 */
static void
init_fctx_key()
{
    (void)pthread_key_create(&fctx_key, destroy_fctx_pool);
}

/**
 * @brief Get thread-private pool of free memory contexts.
 */
static fctx_pool_t *
get_fctx_pool()
{
    fctx_pool_t *fctx_pool = NULL;

    (void)pthread_once(&fctx_init_once, init_fctx_key);
    if ((fctx_pool = (fctx_pool_t *)pthread_getspecific(fctx_key)) == NULL) {
        fctx_pool = calloc(1, sizeof *fctx_pool);
        if (fctx_pool) {
            if (SR_ERR_OK == sr_llist_init(&fctx_pool->fctx_llist)) {
                (void)pthread_setspecific(fctx_key, fctx_pool);
            } else {
                free(fctx_pool);
                fctx_pool = NULL;
            }
        }
    }
    return fctx_pool;
}

int
sr_mem_new(size_t min_size, sr_mem_ctx_t **sr_mem_p)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG(sr_mem_p);

#ifndef USE_SR_MEM_MGMT
    *sr_mem_p = NULL;
    return rc;
#else

    sr_mem_ctx_t *sr_mem = NULL;
    sr_mem_block_t *mem_block = NULL;
    sr_llist_node_t *node_ll = NULL;
    fctx_pool_t *fctx_pool = get_fctx_pool();
    size_t max_recent_peak = 0;

    if (NULL == fctx_pool) {
        SR_LOG_WRN_MSG("Failed to get pool of free memory contexts.");
    } else {
        /* compute maximum recent peak memory usage to piggy-back */
        for (size_t i = 0; i < MEM_PEAK_USAGE_HISTORY_LENGTH; ++i) {
            max_recent_peak = MAX(max_recent_peak, fctx_pool->peak_history[i]);
        }
        if (0 < fctx_pool->count) {
            node_ll = fctx_pool->fctx_llist->last;
            /* find the first suitable context starting from the last used (for cache locality) */
            while (node_ll) {
                sr_mem = (sr_mem_ctx_t *)node_ll->data;
                if (min_size <= ((sr_mem_block_t *)sr_mem->mem_blocks->first->data)->size) {
                    sr_llist_rm(fctx_pool->fctx_llist, node_ll);
                    break;
                } else {
                    sr_mem = NULL;
                }
                node_ll = node_ll->prev;
            }
            if (NULL == sr_mem) {
                /* take also a non-suitable context */
                sr_mem = (sr_mem_ctx_t *)fctx_pool->fctx_llist->last->data;
                sr_llist_rm(fctx_pool->fctx_llist, fctx_pool->fctx_llist->last);
            }
            --fctx_pool->count;
            sr_mem->piggy_back = max_recent_peak;
            *sr_mem_p = sr_mem;
            return SR_ERR_OK;
        }
    }

    sr_mem = calloc(1, sizeof *sr_mem);
    CHECK_NULL_NOMEM_GOTO(sr_mem, rc, cleanup);

    mem_block = malloc(sizeof *mem_block + MAX(min_size, MEM_BLOCK_MIN_SIZE));
    CHECK_NULL_NOMEM_GOTO(mem_block, rc, cleanup);
    mem_block->size = MAX(min_size, MEM_BLOCK_MIN_SIZE);

    rc = sr_llist_init(&sr_mem->mem_blocks);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to initialize linked-list.");

    rc = sr_llist_add_new(sr_mem->mem_blocks, mem_block);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to add memory block into a linked-list.");
    sr_mem->size_total += mem_block->size;

    sr_mem->cursor = sr_mem->mem_blocks->last;
    sr_mem->piggy_back = max_recent_peak;
    *sr_mem_p = sr_mem;

cleanup:
    if (SR_ERR_OK != rc) {
        free(mem_block);
        if (sr_mem) {
            sr_llist_cleanup(sr_mem->mem_blocks);
            free(sr_mem);
        }
    }
    return rc;
#endif /* USE_SR_MEM_MGMT */
}

void *
sr_malloc(sr_mem_ctx_t *sr_mem, size_t size)
{
    size_t used_head = 0;
    void *mem = NULL;
    size_t new_size = 0;
    int err = SR_ERR_OK;
    sr_llist_node_t *node_ll = NULL, *for_removal = NULL;
    sr_mem_block_t *mem_block = NULL;

    if (0 == size) {
        return NULL;
    }

    if (NULL == sr_mem) {
        return malloc(size);
    }

    /* first consider previous blocks */
    node_ll = sr_mem->cursor->prev;
    used_head = QUEUE_PREV(sr_mem->used_head, MAX_BLOCKS_AVAIL_FOR_ALLOC);
    for (size_t i = 0; node_ll && i < MAX_BLOCKS_AVAIL_FOR_ALLOC-1;
         ++i, node_ll = node_ll->prev, used_head = QUEUE_PREV(used_head, MAX_BLOCKS_AVAIL_FOR_ALLOC)) {
        mem_block = (sr_mem_block_t *)node_ll->data;
        if (mem_block->size >= sr_mem->used[used_head] + size) {
            goto alloc;
        }

    }

    /* find first suitable block starting at the cursor */
    used_head = sr_mem->used_head;
    mem_block = (sr_mem_block_t *)sr_mem->cursor->data;
    while (mem_block->size < sr_mem->used[used_head] + size) {
        /* not enough memory in the current block */
        if (0 == sr_mem->used[used_head]) {
            /* don't keep completely empty block in the middle */
            for_removal = sr_mem->cursor;
        } else {
            /* We may still use something from previous blocks in the future,
             * but count the skipped free bytes as used anyway for simplicity. */
            sr_mem->used_total += mem_block->size - sr_mem->used[used_head];
            for_removal = NULL;
        }
        if (sr_mem->cursor == sr_mem->mem_blocks->last) {
            /* add new block */
            new_size = MAX(size, mem_block->size + (mem_block->size >> 1) /* 1.5x */);
            mem_block = (sr_mem_block_t *)malloc(sizeof *mem_block + new_size);
            CHECK_NULL_NOMEM_GOTO(mem_block, err, cleanup);
            mem_block->size = new_size;
            err = sr_llist_add_new(sr_mem->mem_blocks, mem_block);
            CHECK_RC_MSG_GOTO(err, cleanup, "Failed to add memory block into a linked-list.");
            sr_mem->size_total += mem_block->size;
        }
        /* move to the next block */
        assert(sr_mem->cursor->next);
        sr_mem->cursor = sr_mem->cursor->next;
        if (NULL == for_removal) {
            sr_mem->used_head += 1;
            sr_mem->used_head %= MAX_BLOCKS_AVAIL_FOR_ALLOC;
            used_head = sr_mem->used_head;
            sr_mem->used[used_head] = 0;
        }
        assert(sr_mem->cursor->data);
        mem_block = (sr_mem_block_t *)sr_mem->cursor->data;
        if (NULL != for_removal) {
            sr_mem->size_total -= ((sr_mem_block_t *)for_removal->data)->size;
            free(for_removal->data);
            sr_llist_rm(sr_mem->mem_blocks, for_removal);
        }
    }

alloc:
    mem = mem_block->mem + sr_mem->used[used_head];
    sr_mem->used[used_head] += size;
    assert(mem_block->size >= sr_mem->used[used_head]);
    if (used_head == sr_mem->used_head) {
        /* current block */
        sr_mem->used_total += size;
        sr_mem->peak = MAX(sr_mem->used_total, sr_mem->peak);
    } else {
        /* previous block */
        /* already counted as used_total */
    }

cleanup:
    if (SR_ERR_OK != err) {
        if (mem_block) {
            free(mem_block->mem);
            free(mem_block);
        }
    }
    return mem;
}

void *
sr_realloc(sr_mem_ctx_t *sr_mem, void *ptr, size_t old_size, size_t new_size)
{
    size_t used_head = 0, i = 0;
    sr_llist_node_t *node_ll = NULL;
    sr_mem_block_t *mem_block = NULL;
    bool free_end_block = 0;
    void *new_ptr = NULL;

    if (NULL == sr_mem) {
        return realloc(ptr, new_size);
    }

    if (NULL == ptr || old_size == 0) {
        return sr_malloc(sr_mem, new_size);
    }

    if (0 == new_size || old_size > new_size) {
        return NULL;
    }

    /* find the memory block of ptr */
    node_ll = sr_mem->cursor;
    used_head = sr_mem->used_head;
    for (i = 0; node_ll && i < MAX_BLOCKS_AVAIL_FOR_ALLOC;
         ++i, node_ll = node_ll->prev, used_head = QUEUE_PREV(used_head, MAX_BLOCKS_AVAIL_FOR_ALLOC)) {

        mem_block = (sr_mem_block_t *)node_ll->data;
        /* found it */
        if ((char *)ptr >= mem_block->mem && (char *)ptr < mem_block->mem + mem_block->size) {
            /* good case - the memory is currently at the end of a memory block */
            if ((char *)ptr + old_size == mem_block->mem + sr_mem->used[used_head]) {
                /* great case - we can simply extend the current memory */
                if (mem_block->size >= sr_mem->used[used_head] + (new_size - old_size)) {
                    sr_mem->used[used_head] += new_size - old_size;
                    if (used_head == sr_mem->used_head) {
                        /* current block */
                        sr_mem->used_total += new_size - old_size;
                        sr_mem->peak = MAX(sr_mem->used_total, sr_mem->peak);
                    } /* else previous block, already counted as used_total */
                    return ptr;

                /* well, we can at least "free" the current memory, but after malloc
                 * so that this block does not get freed (if it remains empty) */
                } else {
                    free_end_block = 1;
                }
            }
            break;
        }
    }

    /* it must have been found, otherwise the input was invalid */
    assert(node_ll && i < MAX_BLOCKS_AVAIL_FOR_ALLOC);

    /* bad case - we must move the memory somewhere else */
    new_ptr = sr_malloc(sr_mem, new_size);
    if (NULL == new_ptr) {
        return NULL;
    }

    /* copy the current data */
    memcpy(new_ptr, ptr, old_size);

    /* "free" the previous memory chunk, if possible */
    if (free_end_block) {
        sr_mem->used[used_head] -= old_size;
        sr_mem->used_total -= old_size;
        /* the old memory took a whole block, we can actually free it now */
        if (0 == sr_mem->used[used_head]) {
            sr_mem->size_total -= mem_block->size;
            free(mem_block);
            sr_llist_rm(sr_mem->mem_blocks, node_ll);
            memmove(sr_mem->used + used_head, sr_mem->used + used_head + 1, (MAX_BLOCKS_AVAIL_FOR_ALLOC - used_head - 1) * sizeof *sr_mem->used);
            sr_mem->used[MAX_BLOCKS_AVAIL_FOR_ALLOC - 1] = 0;
            assert(sr_mem->used_head);
            --sr_mem->used_head;
        }
    }

    return new_ptr;
}

void *
sr_calloc(sr_mem_ctx_t *sr_mem, size_t nmemb, size_t size)
{
    void *mem = NULL;

    if (NULL == sr_mem) {
        return calloc(nmemb, size);
    }

    mem = sr_malloc(sr_mem, nmemb * size);
    if (NULL != mem) {
        memset(mem, '\0', nmemb * size);
    }
    return mem;
}

/**
 * @brief Completely destroys Sysrepo memory context.
 */
static void
sr_mem_destroy(sr_mem_ctx_t *sr_mem)
{
    if (NULL != sr_mem) {
        sr_llist_node_t *node_ll = sr_mem->mem_blocks->first;
        while (node_ll) {
            sr_mem_block_t *mem_block = (sr_mem_block_t *)node_ll->data;
            free(mem_block);
            node_ll = node_ll->next;
        }
        sr_llist_cleanup(sr_mem->mem_blocks);
        free(sr_mem);
    }
}

void
sr_mem_free(sr_mem_ctx_t *sr_mem)
{
    if (NULL == sr_mem) {
        return;
    }

    fctx_pool_t *fctx_pool = get_fctx_pool();

    if (sr_mem->obj_count) {
        SR_LOG_WRN_MSG("Deallocation of Sysrepo memory context with non-zero usage counter.");
    }

    if (NULL == fctx_pool) {
        SR_LOG_WRN_MSG("Failed to get pool of free memory contexts.");
    } else {
        /* store the information about the peak memory usage into a fixed-size queue */
        fctx_pool->peak_history[fctx_pool->peak_history_head++] = sr_mem->peak;
        fctx_pool->peak_history_head %= MEM_PEAK_USAGE_HISTORY_LENGTH;
        fctx_pool->pb_peak_history[fctx_pool->pb_peak_history_head++] = sr_mem->piggy_back;
        fctx_pool->pb_peak_history_head %= MEM_PEAK_USAGE_HISTORY_LENGTH;
        /* calculate maximum peak memory usage from the recorded history of this thread and potenitally other threads */
        size_t max_recent_peak = 0;
        for (size_t i = 0; i < MEM_PEAK_USAGE_HISTORY_LENGTH; ++i) {
            max_recent_peak = MAX(max_recent_peak, MAX(fctx_pool->pb_peak_history[i], fctx_pool->peak_history[i]));
        }
        if (MAX_FREE_MEM_CONTEXTS > fctx_pool->count) {
            /* remove extra trailing empty memory blocks based on the maximum peak memory usage in the recent history */
            sr_llist_node_t *node_ll = sr_mem->mem_blocks->last;
            while (node_ll->prev) {
                sr_mem_block_t *mem_block = (sr_mem_block_t *)node_ll->data;
                if (sr_mem->size_total - mem_block->size < max_recent_peak + MEM_BLOCK_MIN_SIZE /* plus some extra bytes */) {
                    break;
                }
                node_ll = node_ll->prev;
                sr_mem->size_total -= mem_block->size;
            }
            while (node_ll != sr_mem->mem_blocks->last) {
                sr_mem_block_t *mem_block = (sr_mem_block_t *)sr_mem->mem_blocks->last->data;
                free(mem_block);
                sr_llist_rm(sr_mem->mem_blocks, sr_mem->mem_blocks->last);
            }
            sr_mem->cursor = sr_mem->mem_blocks->first;
            memset(sr_mem->used, 0, sizeof(sr_mem->used));
            sr_mem->used_head = 0;
            sr_mem->used_total = 0;
            sr_mem->peak = 0;
            sr_mem->piggy_back = 0;
            sr_mem->obj_count = 0;
            sr_llist_add_new(fctx_pool->fctx_llist, sr_mem);
            ++fctx_pool->count;
            return;
        }
    }

    sr_mem_destroy(sr_mem);
}

static void
*sr_protobuf_malloc(void *sr_mem, size_t size)
{
    return sr_malloc((sr_mem_ctx_t *)sr_mem, size);
}

static void
sr_protobuf_free(void *sr_mem, void *ptr)
{
    if (NULL == sr_mem) {
        free(ptr);
    }
    /* else do nothing */
}

ProtobufCAllocator
sr_get_protobuf_allocator(sr_mem_ctx_t *sr_mem)
{
    ProtobufCAllocator proto_allocator;
    proto_allocator.allocator_data = (void *)sr_mem;
    proto_allocator.alloc = sr_protobuf_malloc;
    proto_allocator.free = sr_protobuf_free;
    return proto_allocator;
}

void
sr_mem_snapshot(sr_mem_ctx_t *sr_mem, sr_mem_snapshot_t *snapshot)
{
    if (NULL == sr_mem || NULL == snapshot) {
        return; /* NOOP */
    }
    snapshot->sr_mem = sr_mem;
    snapshot->mem_block = sr_mem->cursor;
    memcpy(snapshot->used, sr_mem->used, sizeof(sr_mem->used));
    snapshot->used_head = sr_mem->used_head;
    snapshot->used_total = sr_mem->used_total;
    snapshot->obj_count = sr_mem->obj_count;
}

void
sr_mem_restore(sr_mem_snapshot_t *snapshot)
{
    if (NULL == snapshot || NULL == snapshot->sr_mem || NULL == snapshot->mem_block) {
        return; /* NOOP */
    }

    snapshot->sr_mem->cursor = snapshot->mem_block;
    memcpy(snapshot->sr_mem->used, snapshot->used, sizeof(snapshot->used));
    snapshot->sr_mem->used_head = snapshot->used_head;
    snapshot->sr_mem->used_total = snapshot->used_total;
    snapshot->sr_mem->obj_count = snapshot->obj_count;
}

int
sr_mem_edit_string(sr_mem_ctx_t *sr_mem, char **string_p, const char *new_val)
{
    char *new_mem = NULL;
    CHECK_NULL_ARG(string_p);

    if (NULL != *string_p && strlen(*string_p) >= strlen(new_val)) {
        /* buffer large enough - overwrite */
        strcpy(*string_p, new_val);
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        /* do not use sr_mem mgmt - use calloc */
        new_mem = strdup(new_val);
        CHECK_NULL_NOMEM_RETURN(new_mem);

        free(*string_p);
        *string_p = new_mem;
    } else {
        /* use sr_mem mgmt */
        new_mem = (char *)sr_malloc(sr_mem, strlen(new_val) + 1);
        if (NULL == new_mem) {
            return SR_ERR_INTERNAL;
        }
        strcpy(new_mem, new_val);
        *string_p = new_mem;
    }

    return SR_ERR_OK;
}

int
sr_mem_edit_string_va(sr_mem_ctx_t *sr_mem, char **string_p, const char *format, va_list args)
{
    char *new_mem = NULL;
    va_list args_copy;
    size_t len = 0;

    CHECK_NULL_ARG2(string_p, format);

    /* determine required length - need to use a copy of args! */
    va_copy(args_copy, args);
    len = vsnprintf(NULL, 0, format, args_copy);
    va_end(args_copy);

    if (NULL != *string_p && strlen(*string_p) >= len) {
        /* buffer large enough - overwrite */
        vsnprintf(*string_p, len + 1, format, args);
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        /* do not use sr_mem mgmt - use calloc */
        new_mem = (char *)calloc(len + 1, sizeof(*new_mem));
        CHECK_NULL_NOMEM_RETURN(new_mem);

        vsnprintf(new_mem, len + 1, format, args);
        free(*string_p);
        *string_p = new_mem;
    } else {
        /* use sr_mem mgmt */
        new_mem = (char *)sr_malloc(sr_mem, len + 1);
        if (NULL == new_mem) {
            return SR_ERR_INTERNAL;
        }
        vsnprintf(new_mem, len + 1, format, args);
        *string_p = new_mem;
    }

    return SR_ERR_OK;
}

void
sr_msg_free(Sr__Msg *msg)
{
    if (NULL == msg) {
        return;
    }

    sr_mem_ctx_t *sr_mem = (sr_mem_ctx_t *)msg->_sysrepo_mem_ctx;

    if (sr_mem) {
        if (ATOMIC_DEC(&sr_mem->obj_count) == 1) {
            sr_mem_free(sr_mem);
        }
    } else if (msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
}
