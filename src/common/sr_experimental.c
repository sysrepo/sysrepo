/**
 * @file sr_experimental.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo utility functions.
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
#define MEM_BLOCK_MIN_SIZE           256
#define MAX_FREE_TRAILING_MEM_BLOCKS 3
#define MAX_FREE_MEM_CONTEXTS        10

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

#undef calloc
#undef malloc
#undef realloc
#undef strdup

#ifdef PRINT_ALLOC_EXECS
# define calloc(n,s)  ({ printf("SR-EXP: Calling real calloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = calloc(n,s); mem; })
# define malloc(s)    ({ printf("SR-EXP: Calling real malloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = malloc(s); mem; })
# define realloc(p,s) ({ printf("SR-EXP: Calling real realloc.\n"); inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = realloc(p,s); mem; })
# define strdup(s)    ({ printf("SR-EXP: Calling real strdup.\n"); inc_real_by_exp_alloc(strlen(s)+1); inc_real_alloc(strlen(s)+1); char *str = strdup(s); str; })
#else
# define calloc(n,s)  ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = calloc(n,s); mem; })
# define malloc(s)    ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = malloc(s); mem; })
# define realloc(p,s) ({ inc_real_by_exp_alloc(s); inc_real_alloc(s); void *mem = realloc(p,s); mem; })
# define strdup(s)    ({ inc_real_by_exp_alloc(strlen(s)+1); inc_real_alloc(strlen(s)+1); char *str = strdup(s); str; })
#endif

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

/**
 * @brief A Pool of free memory contexts.
 */
typedef struct fctx_pool_s {
    sr_llist_t *fctx_llist;  /**< Free memory contexts (items are of type sr_mem_ctx_t). */
    size_t count;            /**< Number of free memory contexts. */
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

    if (NULL == fctx_pool) {
        SR_LOG_WRN_MSG("Failed to get pool of free memory contexts.");
    } else {
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
            *sr_mem_p = sr_mem;
            inc_reused_sr_mem();
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

    sr_mem->cursor = sr_mem->mem_blocks->last;
    *sr_mem_p = sr_mem;
    inc_new_sr_mem();

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
    void *mem = NULL;
    size_t new_size = 0;
    int err = SR_ERR_OK;
    bool fake_alloc = true;
    sr_llist_node_t *for_removal = NULL;
    sr_mem_block_t *mem_block = NULL;

    if (0 == size) {
        return NULL;
    }

    if (NULL == sr_mem) {
        return malloc(size);
    }

    /* find first suitable block starting at the cursor */
    mem_block = (sr_mem_block_t *)sr_mem->cursor->data;
    while (mem_block->size < sr_mem->used + size) {
        /* not enough memory in the current block */
        if (0 == sr_mem->used) {
            /* don't keep completely empty block in the middle */
            for_removal = sr_mem->cursor;
        } else {
            for_removal = NULL;
        }
        if (sr_mem->cursor == sr_mem->mem_blocks->last) {
            fake_alloc = false;
            new_size = MAX(size, mem_block->size * 2);
            mem_block = (sr_mem_block_t *)malloc(sizeof *mem_block + new_size);
            CHECK_NULL_NOMEM_GOTO(mem_block, err, cleanup);
            mem_block->size = new_size;
            err = sr_llist_add_new(sr_mem->mem_blocks, mem_block);
            CHECK_RC_MSG_GOTO(err, cleanup, "Failed to add memory block into a linked-list.");
        }
        assert(sr_mem->cursor->next);
        sr_mem->cursor = sr_mem->cursor->next;
        assert(sr_mem->cursor->data);
        mem_block = (sr_mem_block_t *)sr_mem->cursor->data;
        sr_mem->used = 0;
        if (NULL != for_removal) {
            free(for_removal->data);
            sr_llist_rm(sr_mem->mem_blocks, for_removal);
        }
    }

    if (fake_alloc) {
#ifdef PRINT_ALLOC_EXECS
        printf("SR-EXP: Calling fake alloc.\n");
#endif
        inc_fake_alloc(size);
    }

    mem = mem_block->mem + sr_mem->used;
    sr_mem->used += size;

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

    if (sr_mem->ucount) {
        SR_LOG_WRN_MSG("Deallocation of Sysrepo memory context with non-zero usage counter.");
    }

    if (NULL == fctx_pool) {
        SR_LOG_WRN_MSG("Failed to get pool of free memory contexts.");
    } else {
        if (MAX_FREE_MEM_CONTEXTS > fctx_pool->count) {
            /**
             * Simulate snapshot right after ::sr_mem_new in order to zero counters and deallocate
             * extra trailing free memory blocks.
             */
            sr_mem_snapshot_t free_ctx = { sr_mem, sr_mem->mem_blocks->first, 0, 0 };
            sr_mem_restore(free_ctx);
            sr_llist_add_new(fctx_pool->fctx_llist, sr_mem);
            ++fctx_pool->count;
            return;
        }
    }

    sr_mem_destroy(sr_mem);
}

size_t
sr_mem_get_total_usage(sr_mem_ctx_t *sr_mem)
{
    size_t usage = 0;

    if (NULL != sr_mem) {
        sr_llist_node_t *node_ll = sr_mem->mem_blocks->first;
        while (node_ll != sr_mem->cursor) {
            sr_mem_block_t *mem_block = (sr_mem_block_t *)node_ll->data;
            usage += mem_block->size;
            node_ll = node_ll->next;
        }
        usage += sr_mem->used;
    }

    return usage;
}

size_t
sr_mem_get_total_size(sr_mem_ctx_t *sr_mem)
{
    size_t size = 0;

    if (NULL != sr_mem) {
        sr_llist_node_t *node_ll = sr_mem->mem_blocks->first;
        while (NULL != node_ll) {
            sr_mem_block_t *mem_block = (sr_mem_block_t *)node_ll->data;
            size += mem_block->size;
            node_ll = node_ll->next;
        }
    }

    return size;
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
    snapshot->used = sr_mem->used;
    snapshot->ucount = sr_mem->ucount;
}

void
sr_mem_restore(sr_mem_snapshot_t snapshot)
{
    if (NULL == snapshot.sr_mem || NULL == snapshot.mem_block) {
        return; /* NOOP */
    }

    snapshot.sr_mem->cursor = snapshot.mem_block;
    snapshot.sr_mem->used = snapshot.used;
    snapshot.sr_mem->ucount = snapshot.ucount;

    /* remove extra trailing empty memory blocks */
    size_t empty_count = 0;
    sr_llist_node_t *node_ll = snapshot.sr_mem->cursor;
    while (node_ll->next && empty_count < MAX_FREE_TRAILING_MEM_BLOCKS) {
        ++empty_count;
        node_ll = node_ll->next;
    }
    while (node_ll != snapshot.sr_mem->mem_blocks->last) {
        sr_mem_block_t *mem_block = (sr_mem_block_t *)snapshot.sr_mem->mem_blocks->last->data;
        free(mem_block);
        sr_llist_rm(snapshot.sr_mem->mem_blocks, snapshot.sr_mem->mem_blocks->last);
    }
    assert(snapshot.sr_mem->cursor->data);
}

int
sr_mem_edit_string(sr_mem_ctx_t *sr_mem, char **string_p, const char *new_val)
{
    char *new_mem = NULL;
    CHECK_NULL_ARG2(string_p, new_val);

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
        if (0 == --sr_mem->ucount) {
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
    value->sr_mem = sr_mem;
    sr_mem->ucount = 1;

    if (xpath) {
        ret = sr_val_set_xpath(value, xpath);
        if (SR_ERR_OK != ret) {
            sr_mem_free(sr_mem);
            return SR_ERR_INTERNAL;
        }
    }

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
        values[i].sr_mem = sr_mem;
    }
    sr_mem->ucount = 1; /* 1 for the entire array */

    *values_p = values;
    return SR_ERR_OK;
}

int
sr_val_set_xpath(sr_val_t *value, const char *xpath)
{
    CHECK_NULL_ARG2(value, xpath);
    return sr_mem_edit_string(value->sr_mem, &value->xpath, xpath);
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

    return sr_mem_edit_string(value->sr_mem, to_edit, string_val);
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
