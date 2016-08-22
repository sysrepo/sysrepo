/**
 * @file sr_experimental.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo experimental memory management implementation.
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

#include "sr_experimental.h"
#include "sr_common.h"

/* Configuration */
#define MEM_BLOCK_MIN_SIZE            256
#define MAX_FREE_MEM_CONTEXTS         4
#define MEM_PEAK_USAGE_HISTORY_LENGTH 3

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#define QUEUE_PREV(head, len) ((head) == 0 ? ((len)-1) : ((head)-1))

#undef calloc
#undef malloc
#undef realloc
#undef strdup

#ifdef PRINT_ALLOC_STATS
# ifdef PRINT_ALLOC_EXECS
#  define calloc(n,s)  ({ printf("SR-EXP: Calling real calloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = calloc(n,s); mem; })
#  define malloc(s)    ({ printf("SR-EXP: Calling real malloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = malloc(s); mem; })
#  define realloc(p,s) ({ printf("SR-EXP: Calling real realloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = realloc(p,s); mem; })
#  define strdup(s)    ({ printf("SR-EXP: Calling real strdup.\n"); inc_real_by_exp_alloc(strlen(s)+1); inc_real_alloc(strlen(s)+1); char *str = strdup(s); str; })
# else
#  define calloc(n,s)  ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = calloc(n,s); mem; })
#  define malloc(s)    ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = malloc(s); mem; })
#  define realloc(p,s) ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = realloc(p,s); mem; })
#  define strdup(s)    ({ inc_real_by_exp_alloc(strlen(s)+1); inc_real_alloc(strlen(s)+1); char *str = strdup(s); str; })
# endif

size_t real_alloc_count = 0;
size_t real_alloc_size = 0;
size_t real_alloc_by_exp_count = 0;
size_t real_alloc_by_exp_size = 0;
size_t fake_alloc_count = 0;
size_t fake_alloc_size = 0;

size_t new_sr_mem_count = 0;
size_t reused_sr_mem_count = 0;

void inc_real_alloc(size_t size)
{
    __sync_add_and_fetch(&real_alloc_count, 1);
    __sync_add_and_fetch(&real_alloc_size, size);
}

void inc_real_by_exp_alloc(size_t size)
{
    __sync_add_and_fetch(&real_alloc_by_exp_count, 1);
    __sync_add_and_fetch(&real_alloc_by_exp_size, size);
}

void inc_fake_alloc(size_t size)
{
    __sync_add_and_fetch(&fake_alloc_count, 1);
    __sync_add_and_fetch(&fake_alloc_size, size);
}

void inc_new_sr_mem()
{
    __sync_add_and_fetch(&new_sr_mem_count, 1);
}

void inc_reused_sr_mem()
{
    __sync_add_and_fetch(&reused_sr_mem_count, 1);
}

__attribute__((destructor)) void print_mem_alloc_stats()
{
    static int run = 0;
    if (!run) {
        printf("Total number of real allocs: %lu\n", real_alloc_count);
        printf("Total size of real allocs: %lu\n", real_alloc_size);
        printf("Number of real allocs by exp: %lu\n", real_alloc_by_exp_count);
        printf("Size of real allocs by exp: %lu\n", real_alloc_by_exp_size);
        printf("Number of fake allocs: %lu\n", fake_alloc_count);
        printf("Size of fake allocs: %lu\n", fake_alloc_size);
        printf("New sysrepo memory contexts: %lu\n", new_sr_mem_count);
        printf("Reused sysrepo memory contexts: %lu\n", reused_sr_mem_count);
        run = 1;
    }
}
#endif

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
            node_ll = fctx_pool->fctx_llist->first;
            /* find the first suitable context */
            while (node_ll) {
                sr_mem = (sr_mem_ctx_t *)node_ll->data;
                if (min_size <= ((sr_mem_block_t *)sr_mem->mem_blocks->first->data)->size) {
                    sr_llist_rm(fctx_pool->fctx_llist, node_ll);
                    break;
                } else {
                    sr_mem = NULL;
                }
                node_ll = node_ll->next;
            }
            if (NULL == sr_mem) {
                /* take also a non-suitable context */
                sr_mem = (sr_mem_ctx_t *)fctx_pool->fctx_llist->first->data;
                sr_llist_rm(fctx_pool->fctx_llist, fctx_pool->fctx_llist->first);
            }
            --fctx_pool->count;
            sr_mem->piggy_back = max_recent_peak;
            *sr_mem_p = sr_mem;
#ifdef PRINT_ALLOC_STATS
            inc_reused_sr_mem();
#endif
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
#ifdef PRINT_ALLOC_STATS
    inc_new_sr_mem();
#endif

cleanup:
    if (SR_ERR_OK != rc) {
        free(mem_block);
        if (sr_mem) {
            sr_llist_cleanup(sr_mem->mem_blocks);
            free(sr_mem);
        }
    }
    return rc;
}

void
*sr_malloc(sr_mem_ctx_t *sr_mem, size_t size)
{
    size_t used_head = 0;
    void *mem = NULL;
    size_t new_size = 0;
    int err = SR_ERR_OK;
    bool fake_alloc = true;
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
            fake_alloc = false;
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
    if (fake_alloc) {
#ifdef PRINT_ALLOC_EXECS
        printf("SR-EXP: Calling fake alloc.\n");
#endif
#ifdef PRINT_ALLOC_STATS
        inc_fake_alloc(size);
#endif
    }

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

void
*sr_calloc(sr_mem_ctx_t *sr_mem, size_t nmemb, size_t size)
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
sr_protobuf_free(void *mem, void *ptr)
{
    /* do nothing */
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
        /* overwrite */
        strcpy(*string_p, new_val);
        return SR_ERR_OK;
    }

    if (NULL == sr_mem) {
        new_mem = strdup(new_val);
        CHECK_NULL_NOMEM_RETURN(new_mem);
        free(*string_p);
        *string_p = new_mem;
        return SR_ERR_OK;
    }

    new_mem = (char *)sr_malloc(sr_mem, strlen(new_val) + 1);
    if (NULL == new_mem) {
        return SR_ERR_INTERNAL;
    }
    strcpy(new_mem, new_val);
    *string_p = new_mem;
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
        if (0 == --sr_mem->obj_count) {
            sr_mem_free(sr_mem);
        }
    } else if (msg) {
        sr__msg__free_unpacked(msg, NULL);
    }
}



int
sr_new_val(const char *xpath, sr_val_t **value_p)
{
    int ret = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_val_t *value = NULL;

    CHECK_NULL_ARG(value_p);

    ret = sr_mem_new(sizeof *value + (xpath ? strlen(xpath) + 1 : 0), &sr_mem);
    CHECK_RC_MSG_RETURN(ret, "Failed to obtain new sysrepo memory.");
    value = (sr_val_t *)sr_calloc(sr_mem, 1, sizeof *value);
    if (NULL == value) {
        sr_mem_free(sr_mem);
        return SR_ERR_INTERNAL;
    }
    value->_sr_mem = sr_mem;

    if (xpath) {
        ret = sr_val_set_xpath(value, xpath);
        if (SR_ERR_OK != ret) {
            sr_mem_free(sr_mem);
            return SR_ERR_INTERNAL;
        }
    }

    sr_mem->obj_count = 1;
    *value_p = value;
    return SR_ERR_OK;
}

int
sr_new_values(size_t count, sr_val_t **values_p)
{
    int ret = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_val_t *values = NULL;

    CHECK_NULL_ARG(values_p);

    if (0 == count) {
        *values_p = NULL;
        return SR_ERR_OK;
    }

    ret = sr_mem_new((sizeof *values) * count, &sr_mem);
    CHECK_RC_MSG_RETURN(ret, "Failed to obtain new sysrepo memory.");
    values = (sr_val_t *)sr_calloc(sr_mem, count, sizeof *values);
    if (NULL == values) {
        sr_mem_free(sr_mem);
        return SR_ERR_INTERNAL;
    }
    for (size_t i = 0; i < count; ++i) {
        values[i]._sr_mem = sr_mem;
    }
    sr_mem->obj_count = 1; /* 1 for the entire array */

    *values_p = values;
    return SR_ERR_OK;
}

int
sr_val_set_xpath(sr_val_t *value, const char *xpath)
{
    CHECK_NULL_ARG2(value, xpath);
    return sr_mem_edit_string(value->_sr_mem, &value->xpath, xpath);
}

int
sr_val_set_string(sr_val_t *value, const char *string_val)
{
    char **to_edit = NULL;
    CHECK_NULL_ARG2(value, string_val);

    switch (value->type) {
        case SR_BINARY_T:
            to_edit = &value->data.binary_val;
            break;
        case SR_BITS_T:
            to_edit = &value->data.bits_val;
            break;
        case SR_ENUM_T:
            to_edit = &value->data.enum_val;
            break;
        case SR_IDENTITYREF_T:
            to_edit = &value->data.identityref_val;
            break;
        case SR_INSTANCEID_T:
            to_edit = &value->data.instanceid_val;
            break;
        case SR_STRING_T:
            to_edit = &value->data.string_val;
            break;
        default:
            return SR_ERR_INVAL_ARG;
    }

    return sr_mem_edit_string(value->_sr_mem, to_edit, string_val);
}

static int
sr_dup_val_data(sr_val_t *dest, sr_val_t *source)
{
    int rc = SR_ERR_OK;
    CHECK_NULL_ARG2(source, dest);

    dest->dflt = source->dflt;
    dest->type = source->type;

    switch (source->type) {
        case SR_BINARY_T:
            rc = sr_val_set_string(dest, source->data.binary_val);
            break;
        case SR_BITS_T:
            rc = sr_val_set_string(dest, source->data.bits_val);
            break;
        case SR_ENUM_T:
            rc = sr_val_set_string(dest, source->data.enum_val);
            break;
        case SR_IDENTITYREF_T:
            rc = sr_val_set_string(dest, source->data.identityref_val);
            break;
        case SR_INSTANCEID_T:
            rc = sr_val_set_string(dest, source->data.instanceid_val);
            break;
        case SR_STRING_T:
            rc = sr_val_set_string(dest, source->data.string_val);
            break;
        case SR_BOOL_T:
        case SR_DECIMAL64_T:
        case SR_INT8_T:
        case SR_INT16_T:
        case SR_INT32_T:
        case SR_INT64_T:
        case SR_UINT8_T:
        case SR_UINT16_T:
        case SR_UINT32_T:
        case SR_UINT64_T:
            dest->data = source->data;
        default:
            break;
    }

    return rc;
}

int
sr_dup_val(sr_val_t *value, sr_val_t **value_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *val_dup = NULL;

    CHECK_NULL_ARG2(value, value_dup_p);

    rc = sr_new_val(value->xpath, &val_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new sysrepo value.");

    rc = sr_dup_val_data(val_dup, value);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");

    *value_dup_p = val_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_val(val_dup);
    }

    return rc;
}

int
sr_dup_values(sr_val_t *values, size_t count, sr_val_t **values_dup_p)
{
    int rc = SR_ERR_OK;
    sr_val_t *values_dup = NULL;

    CHECK_NULL_ARG2(values, values_dup_p);

    rc = sr_new_values(count, &values_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new array of sysrepo values.");

    for (size_t i = 0; i < count; ++i) {
        sr_val_set_xpath(values_dup + i, values[i].xpath);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value xpath.");
        rc = sr_dup_val_data(values_dup + i, values + i);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");
    }

    *values_dup_p = values_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_values(values_dup, count);
    }

    return rc;
}



/**
 * @brief Allocate a new instance of a sysrepo node over an existing sysrepo memory context.
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

int
sr_new_tree(const char *name, const char *module_name, sr_node_t **node_p)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;

    CHECK_NULL_ARG(node_p);

    rc = sr_mem_new(sizeof(sr_node_t) + (name ? strlen(name) + 1 : 0)
                                      + (module_name ? strlen(module_name) + 1 : 0),
                    &sr_mem);
    CHECK_RC_MSG_RETURN(rc, "Failed to obtain new sysrepo memory.");

    rc = sr_new_node(sr_mem, name, module_name, node_p);
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
    } else {
        sr_mem->obj_count = 1;
    }

    return rc;
}

int
sr_new_trees(size_t count, sr_node_t **trees_p)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    sr_node_t *trees = NULL;

    CHECK_NULL_ARG(trees_p);

    if (0 == count) {
        *trees_p = NULL;
        return SR_ERR_OK;
    }

    rc = sr_mem_new((sizeof *trees) * count, &sr_mem);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to obtain new sysrepo memory.");
    trees = (sr_node_t *)sr_calloc(sr_mem, count, sizeof *trees);
    CHECK_NULL_NOMEM_GOTO(trees, rc, cleanup);
    for (size_t i = 0; i < count; ++i) {
        trees[i]._sr_mem = sr_mem;
    }
    sr_mem->obj_count = 1; /* 1 for the entire array */

cleanup:
    if (SR_ERR_OK != rc) {
        sr_mem_free(sr_mem);
    } else {
        *trees_p = trees;
    }
    return SR_ERR_OK;
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
static void
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
    child->prev = parent->last_child;
    child->next = NULL;
    parent->last_child = child;
    child->parent = parent;
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

static int
sr_dup_tree_ctx(sr_mem_ctx_t *sr_mem, sr_node_t *tree, sr_node_t **tree_dup_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *tree_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG2(tree, tree_dup_p);

    if (NULL != sr_mem) {
        rc = sr_new_node(sr_mem, tree->name, tree->module_name, &tree_dup);
    } else {
        rc = sr_new_tree(tree->name, tree->module_name, &tree_dup);
    }
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new sysrepo node.");

    rc = sr_dup_val_data((sr_val_t *)tree_dup, (sr_val_t *)tree);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node data.");

    /* duplicate descendants */
    child = tree->first_child;
    while (child) {
        rc = sr_dup_tree_ctx(tree_dup->_sr_mem, child, &child_dup);
        if (SR_ERR_OK != rc) {
            goto cleanup;
        }
        sr_node_insert_child(tree_dup, child_dup);
        child = child->next;
    }

    *tree_dup_p = tree_dup;

cleanup:
    if (SR_ERR_OK != rc && NULL == sr_mem) {
        sr_free_tree(tree_dup);
    }

    return rc;
}

int
sr_dup_tree(sr_node_t *tree, sr_node_t **tree_dup_p)
{
    return sr_dup_tree_ctx(NULL, tree, tree_dup_p);
}

int
sr_dup_trees(sr_node_t *trees, size_t count, sr_node_t **trees_dup_p)
{
    int rc = SR_ERR_OK;
    sr_node_t *trees_dup = NULL, *child = NULL, *child_dup = NULL;

    CHECK_NULL_ARG2(trees, trees_dup_p);

    rc = sr_new_trees(count, &trees_dup);
    CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to create new array of sysrepo nodes.");

    for (size_t i = 0; i < count; ++i) {
        sr_node_set_name(trees_dup + i, trees[i].name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo node name.");
        sr_node_set_module(trees_dup + i, trees[i].module_name);
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate module of a sysrepo node.");
        rc = sr_dup_val_data((sr_val_t *)(trees_dup + i), (sr_val_t *)(trees + i));
        CHECK_RC_MSG_GOTO(rc, cleanup, "Failed to duplicate sysrepo value data.");

        /* duplicate descendants */
        child = trees[i].first_child;
        while (child) {
            rc = sr_dup_tree_ctx(trees_dup->_sr_mem, child, &child_dup);
            if (SR_ERR_OK != rc) {
                goto cleanup;
            }
            sr_node_insert_child(trees_dup + i, child_dup);
            child = child->next;
        }
    }

    *trees_dup_p = trees_dup;

cleanup:
    if (SR_ERR_OK != rc) {
        sr_free_trees(trees_dup, count);
    }

    return rc;
}
