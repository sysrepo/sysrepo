/**
 * @file mem_mgmt_test.c
 * @author Rastislav Szabo <raszabo@cisco.com>, Lukas Macko <lmacko@cisco.com>,
 *         Milan Lenco <milan.lenco@pantheon.tech>
 * @brief Sysrepo memory management unit tests.
 *
 * @copyright
 * Copyright 2015 Cisco Systems, Inc.
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

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <unistd.h>
#include <setjmp.h>
#include <cmocka.h>
#include <fcntl.h>
#include <sys/stat.h>

#include "sr_common.h"
#include "system_helper.h"

/**
 * @brief Get number of memory blocks allocated in a context.
 */
static size_t
get_num_of_mem_blocks(const sr_mem_ctx_t *sr_mem)
{
    size_t count = 0;
    sr_llist_node_t *node = sr_mem->mem_blocks->first;

    while (node) {
        ++count;
        node = node->next;
    }
    return count;
}

/**
 * @brief Check number of memory blocks allocated in a context.
 */
static void
check_num_of_mem_blocks(const sr_mem_ctx_t *sr_mem, size_t expected)
{
    assert_int_equal(expected, get_num_of_mem_blocks(sr_mem));
}

/**
 * @brief Check usage of the last MAX_BLOCKS_AVAIL_FOR_ALLOC blocks.
 */
static void
check_mem_block_usage(sr_mem_ctx_t *sr_mem, ...)
{
    va_list va;
    size_t usage;

    va_start(va, sr_mem);
    for (size_t i = 0; i < MAX_BLOCKS_AVAIL_FOR_ALLOC; ++i) {
        usage = va_arg(va, size_t);
        assert_int_equal(sr_mem->used[(sr_mem->used_head + i + 1) % MAX_BLOCKS_AVAIL_FOR_ALLOC], usage);
    }
    va_end(va);
}

/**
 * @brief Get memory block at the given index.
 */
static const sr_mem_block_t *
get_mem_block(sr_mem_ctx_t *sr_mem, ssize_t index)
{
    assert_non_null(sr_mem->mem_blocks->first);
    ssize_t total = get_num_of_mem_blocks(sr_mem);

    assert_true(index < total);
    if (index < 0) {
        index += total;
    }
    assert_true(index >= 0);

    sr_llist_node_t *node = sr_mem->mem_blocks->first;

    while (index) {
        node = node->next;
        assert_non_null(node);
        --index;
    }
    return (sr_mem_block_t *)node->data;
}

static void
sr_mem_new_test (void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL, *sr_mem2 = NULL, *sr_mem_old = NULL;
    const sr_mem_block_t *mem_block = NULL;

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(sr_mem);
    check_num_of_mem_blocks(sr_mem, 1);
    check_mem_block_usage(sr_mem, 0, 0, 0);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(0, sr_mem->peak);
    assert_int_equal(0, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(MEM_BLOCK_MIN_SIZE, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_non_null(mem_block->mem);
    assert_int_equal(MEM_BLOCK_MIN_SIZE, mem_block->size);
    sr_mem_old = sr_mem;
    sr_mem_free(sr_mem);

    rc = sr_mem_new(MEM_BLOCK_MIN_SIZE * 10 /* this is only hint */, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(sr_mem);
    assert_ptr_equal(sr_mem, sr_mem_old); /* reused */
    check_num_of_mem_blocks(sr_mem, 1);
    check_mem_block_usage(sr_mem, 0, 0, 0);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(0, sr_mem->peak);
    assert_int_equal(0, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(MEM_BLOCK_MIN_SIZE, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_non_null(mem_block->mem);
    assert_int_equal(MEM_BLOCK_MIN_SIZE, mem_block->size);

    rc = sr_mem_new(MEM_BLOCK_MIN_SIZE * 10, &sr_mem2);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(sr_mem2);
    assert_ptr_not_equal(sr_mem2, sr_mem); /* NOT reused */
    check_num_of_mem_blocks(sr_mem2, 1);
    check_mem_block_usage(sr_mem2, 0, 0, 0);
    assert_ptr_equal(sr_mem2->cursor, sr_mem2->mem_blocks->first);
    assert_int_equal(0, sr_mem2->peak);
    assert_int_equal(0, sr_mem2->used_total);
    assert_int_equal(0, sr_mem2->obj_count);
    assert_int_equal(MEM_BLOCK_MIN_SIZE * 10, sr_mem2->size_total);
    mem_block = get_mem_block(sr_mem2, -1);
    assert_non_null(mem_block->mem);
    assert_int_equal(MEM_BLOCK_MIN_SIZE * 10, mem_block->size);

    sr_mem_free(sr_mem2);
    sr_mem_free(sr_mem);
}

static void
sr_malloc_test (void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0, mem_block1_size = MEM_BLOCK_MIN_SIZE;
    size_t mem_block2_size = MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE >> 1);
    const sr_mem_block_t *mem_block = NULL;
    void *mem = NULL;

    /* standard malloc */
    mem = sr_malloc(NULL, 10);
    assert_non_null(mem);
    free(mem);

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    /* sysrepo malloc, 10 bytes */
    size = 10;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 1);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(size, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo malloc, 10 bytes */
    size = 10;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 1);
    check_mem_block_usage(sr_mem, 0, 0, 2*size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(2*size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + size, mem);

    /* sysrepo malloc, (MEM_BLOCK_MIN_SIZE-20) bytes */
    size = mem_block1_size - 20;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 1);
    check_mem_block_usage(sr_mem, 0, 0, mem_block1_size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(mem_block1_size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + 20, mem);

    /* sysrepo malloc, (1.5*MEM_BLOCK_MIN_SIZE - 10) bytes */
    size = mem_block2_size - 10;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 2);
    check_mem_block_usage(sr_mem, 0, MEM_BLOCK_MIN_SIZE, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(mem_block1_size + size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size + mem_block2_size, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo malloc, 1 MiB */
    size = 1 << 20;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size - 10, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size + mem_block2_size + size, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -1);
    assert_int_equal(size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo malloc, 10 bytes (from the second block) */
    size = 10;
    mem = sr_malloc(sr_mem, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size, 1 << 20);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(mem_block1_size + mem_block2_size + (1<<20), sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, -2);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + mem_block->size - 10, mem);

    sr_mem_free(sr_mem);
}

static void
sr_realloc_test (void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0;
    size_t mem_block1_size = MEM_BLOCK_MIN_SIZE;
    size_t mem_block2_size = MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE >> 1);
    const sr_mem_block_t *mem_block = NULL;
    void *mem = NULL, *mem2 = NULL;

    /* fctx pool is reused from sr_malloc_test, so we have much bugger pool :-/ */
    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    /* sysrepo realloc, new 10 bytes */
    size = 10;
    mem = sr_realloc(sr_mem, NULL, 0, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(size, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo realloc, to 20 bytes */
    size = 20;
    mem = sr_realloc(sr_mem, mem, 10, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo realloc, to MEM_BLOCK_MIN_SIZE bytes */
    size = mem_block1_size;
    mem = sr_realloc(sr_mem, mem, 20, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo realloc, to (1.5*MEM_BLOCK_MIN_SIZE - 10) bytes */
    size = mem_block2_size - 10;
    mem = sr_realloc(sr_mem, mem, mem_block1_size, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 2);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total + mem_block1_size, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total + mem_block1_size);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo realloc, new 1 MiB */
    size = 1 << 20;
    mem2 = sr_realloc(sr_mem, NULL, 0, size);
    check_num_of_mem_blocks(sr_mem, 2);
    assert_non_null(mem2);
    check_mem_block_usage(sr_mem, 0, mem_block2_size - 10, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total + mem_block1_size);
    mem_block = get_mem_block(sr_mem, 1);
    assert_int_equal(size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem2);

    /* sysrepo realloc, to (1.5*MEM_BLOCK_MIN_SIZE) bytes (from the first block) */
    size = mem_block2_size;
    mem = sr_realloc(sr_mem, mem, mem_block2_size-10, size);
    assert_non_null(mem);
    check_num_of_mem_blocks(sr_mem, 2);
    check_mem_block_usage(sr_mem, 0, size, 1 << 20);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(sr_mem->piggy_back, sr_mem->size_total + mem_block1_size);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    sr_mem_free(sr_mem);
}

static int
memory_is_zeroed(char *buf, size_t size)
{
    return buf[0] == 0 && !memcmp(buf, buf + 1, size - 1);
}

static void
sr_calloc_test (void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0, mem_block1_size = MEM_BLOCK_MIN_SIZE;
    size_t mem_block2_size = MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE >> 1);
    const size_t size_total = mem_block1_size + mem_block2_size + (1<<20); /* reused from sr_malloc_test */
    const sr_mem_block_t *mem_block = NULL;
    void *mem = NULL;

    /* standard calloc */
    mem = sr_calloc(NULL, 5, 10);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, 50));
    free(mem);

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    /* sysrepo calloc, 10 bytes */
    size = 10;
    mem = sr_calloc(sr_mem, 1, size);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(size, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo calloc, 10 bytes */
    size = 10;
    mem = sr_calloc(sr_mem, 2, size >> 1);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, 2*size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(2*size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + size, mem);

    /* sysrepo calloc, (MEM_BLOCK_MIN_SIZE-20) bytes */
    size = mem_block1_size - 20;
    mem = sr_calloc(sr_mem, 1, size);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, mem_block1_size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(mem_block1_size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_int_equal(mem_block1_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + 20, mem);

    /* sysrepo calloc, (1.5*MEM_BLOCK_MIN_SIZE - 10) bytes */
    size = mem_block2_size - 10;
    mem = sr_calloc(sr_mem, 1, size);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, MEM_BLOCK_MIN_SIZE, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(mem_block1_size + size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 1);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo calloc, 1 MiB */
    size = 1 << 20;
    mem = sr_calloc(sr_mem, 4, size >> 2);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size - 10, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 2);
    assert_int_equal(size, mem_block->size);
    assert_ptr_equal(mem_block->mem, mem);

    /* sysrepo calloc, 10 bytes (from the second block) */
    size = 10;
    mem = sr_calloc(sr_mem, size, 1);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size, 1 << 20);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 1);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + mem_block->size - 10, mem);

    sr_mem_free(sr_mem);
}

static void
sr_mem_snapshot_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0, mem_block1_size = MEM_BLOCK_MIN_SIZE, peak = 0;
    size_t mem_block2_size = MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE >> 1);
    const size_t size_total = mem_block1_size + mem_block2_size + (1<<20); /* reused from sr_malloc_test */
    const sr_mem_block_t *mem_block = NULL;
    sr_mem_snapshot_t snapshot1 = { 0, }, snapshot2 = { 0, };
    void *mem = NULL;

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    sr_mem_snapshot(sr_mem, &snapshot1);
    assert_ptr_equal(sr_mem, snapshot1.sr_mem);
    assert_ptr_equal(sr_mem->cursor, snapshot1.mem_block);
    assert_int_equal(0, memcmp(sr_mem->used, snapshot1.used, MAX_BLOCKS_AVAIL_FOR_ALLOC));
    assert_int_equal(sr_mem->used_total, snapshot1.used_total);
    assert_int_equal(sr_mem->obj_count, snapshot1.obj_count);

    for (int i = 0; i < 3; ++i) {
        /* restore to the original (empty) memory context state */
        sr_mem_restore(&snapshot1);

        /* sysrepo calloc, 10 bytes */
        size = 10;
        mem = sr_calloc(sr_mem, 1, size);
        assert_non_null(mem);
        assert_true(memory_is_zeroed(mem, size));
        check_num_of_mem_blocks(sr_mem, 3);
        check_mem_block_usage(sr_mem, 0, 0, size);
        assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
        assert_int_equal(i == 0 ? size : peak, sr_mem->peak);
        assert_int_equal(size, sr_mem->used_total);
        assert_int_equal(0, sr_mem->obj_count);
        assert_int_equal(size_total, sr_mem->size_total);
        mem_block = get_mem_block(sr_mem, 0);
        assert_int_equal(mem_block1_size, mem_block->size);
        assert_ptr_equal(mem_block->mem, mem);

        /* sysrepo calloc, 10 bytes */
        size = 10;
        mem = sr_calloc(sr_mem, 2, size >> 1);
        assert_non_null(mem);
        assert_true(memory_is_zeroed(mem, size));
        check_num_of_mem_blocks(sr_mem, 3);
        check_mem_block_usage(sr_mem, 0, 0, 2*size);
        assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
        assert_int_equal(i == 0 ? sr_mem->used_total : peak, sr_mem->peak);
        assert_int_equal(2*size, sr_mem->used_total);
        assert_int_equal(0, sr_mem->obj_count);
        assert_int_equal(size_total, sr_mem->size_total);
        mem_block = get_mem_block(sr_mem, 0);
        assert_int_equal(mem_block1_size, mem_block->size);
        assert_ptr_equal(mem_block->mem + size, mem);

        /* sysrepo calloc, (MEM_BLOCK_MIN_SIZE-20) bytes */
        size = mem_block1_size - 20;
        mem = sr_calloc(sr_mem, 1, size);
        assert_non_null(mem);
        assert_true(memory_is_zeroed(mem, size));
        check_num_of_mem_blocks(sr_mem, 3);
        check_mem_block_usage(sr_mem, 0, 0, mem_block1_size);
        assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
        assert_int_equal(i == 0 ? sr_mem->used_total : peak, sr_mem->peak);
        assert_int_equal(mem_block1_size, sr_mem->used_total);
        assert_int_equal(0, sr_mem->obj_count);
        assert_int_equal(size_total, sr_mem->size_total);
        mem_block = get_mem_block(sr_mem, 0);
        assert_int_equal(mem_block1_size, mem_block->size);
        assert_ptr_equal(mem_block->mem + 20, mem);

        /* sysrepo calloc, (1.5*MEM_BLOCK_MIN_SIZE - 10) bytes */
        size = mem_block2_size - 10;
        mem = sr_calloc(sr_mem, 1, size);
        assert_non_null(mem);
        assert_true(memory_is_zeroed(mem, size));
        check_num_of_mem_blocks(sr_mem, 3);
        check_mem_block_usage(sr_mem, 0, MEM_BLOCK_MIN_SIZE, size);
        assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next);
        assert_int_equal(i == 0 ? sr_mem->used_total : peak, sr_mem->peak);
        assert_int_equal(mem_block1_size + size, sr_mem->used_total);
        assert_int_equal(0, sr_mem->obj_count);
        assert_int_equal(size_total, sr_mem->size_total);
        mem_block = get_mem_block(sr_mem, 1);
        assert_int_equal(mem_block2_size, mem_block->size);
        assert_ptr_equal(mem_block->mem, mem);

        sr_mem_snapshot(sr_mem, &snapshot2);
        assert_ptr_equal(sr_mem, snapshot2.sr_mem);
        assert_ptr_equal(sr_mem->cursor, snapshot2.mem_block);
        assert_int_equal(0, memcmp(sr_mem->used, snapshot2.used, MAX_BLOCKS_AVAIL_FOR_ALLOC));
        assert_int_equal(sr_mem->used_total, snapshot2.used_total);
        assert_int_equal(sr_mem->obj_count, snapshot2.obj_count);

        for (int j = 0; j < 4; ++j) {
            /* restore to the second snapshot */
            sr_mem_restore(&snapshot2);

            /* sysrepo calloc, 1 MiB */
            size = 1 << 20;
            mem = sr_calloc(sr_mem, 4, size >> 2);
            peak = sr_mem->used_total;
            assert_non_null(mem);
            assert_true(memory_is_zeroed(mem, size));
            check_num_of_mem_blocks(sr_mem, 3);
            check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size - 10, size);
            assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
            assert_int_equal(peak, sr_mem->peak);
            assert_int_equal(sr_mem->size_total, sr_mem->used_total);
            assert_int_equal(0, sr_mem->obj_count);
            assert_int_equal(size_total, sr_mem->size_total);
            mem_block = get_mem_block(sr_mem, 2);
            assert_int_equal(size, mem_block->size);
            assert_ptr_equal(mem_block->mem, mem);
        }
    }

    /* sysrepo calloc, 10 bytes (from the second block) */
    size = 10;
    mem = sr_calloc(sr_mem, size, 1);
    assert_non_null(mem);
    assert_true(memory_is_zeroed(mem, size));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, mem_block1_size, mem_block2_size, 1 << 20);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first->next->next);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(sr_mem->size_total, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 1);
    assert_int_equal(mem_block2_size, mem_block->size);
    assert_ptr_equal(mem_block->mem + mem_block->size - 10, mem);

    sr_mem_free(sr_mem);
}

static void
sr_mem_edit_string_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0;
    char *string = NULL;
    const sr_mem_block_t *mem_block = NULL;
    const size_t size_total = 2*MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE>>1) + (1<<20); /* reused from sr_malloc_test */

#define STRING_VALUE "String value"
#define SHORTER_STRING_VALUE "value"
#define LONGER_STRING_VALUE "Longer string value"

    /* standard strdup */
    rc = sr_mem_edit_string(NULL, &string, STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, STRING_VALUE));
    rc = sr_mem_edit_string(NULL, &string, SHORTER_STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, SHORTER_STRING_VALUE));
    rc = sr_mem_edit_string(NULL, &string, LONGER_STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, LONGER_STRING_VALUE));
    free(string);
    string = NULL;

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    /* sysrepo "strdup" */
    rc = sr_mem_edit_string(sr_mem, &string, STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    size = strlen(STRING_VALUE) + 1;
    assert_int_equal(0, strcmp(string, STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem, string);

    /* overwrite */
    rc = sr_mem_edit_string(sr_mem, &string, SHORTER_STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, SHORTER_STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem, string);

    /* realloc */
    rc = sr_mem_edit_string(sr_mem, &string, LONGER_STRING_VALUE);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    size += strlen(LONGER_STRING_VALUE) + 1;
    assert_int_equal(0, strcmp(string, LONGER_STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem + strlen(STRING_VALUE) + 1, string);

    sr_mem_free(sr_mem);

#undef STRING_VALUE
#undef SHORTER_STRING_VALUE
#undef LONGER_STRING_VALUE
}

static int
sr_mem_edit_string_va_wrapper(sr_mem_ctx_t *sr_mem, char **string_p, const char *format, ...)
{
    va_list arg_list;
    int rc = SR_ERR_OK;

    va_start(arg_list, format);
    rc = sr_mem_edit_string_va(sr_mem, string_p, format, arg_list);
    va_end(arg_list);

    return rc;
}

static void
sr_mem_edit_string_va_test(void **state)
{
    int rc = SR_ERR_OK;
    sr_mem_ctx_t *sr_mem = NULL;
    size_t size = 0;
    char *string = NULL;
    const sr_mem_block_t *mem_block = NULL;
    const size_t size_total = 2*MEM_BLOCK_MIN_SIZE + (MEM_BLOCK_MIN_SIZE>>1) + (1<<20); /* reused from sr_malloc_test */

#define STRING_TEMPLATE "String value %d"
#define STRING_VALUE "String value 123"
#define SHORTER_STRING_TEMPLATE "value %d"
#define SHORTER_STRING_VALUE "value 456"
#define LONGER_STRING_TEMPLATE "Longer string value %d"
#define LONGER_STRING_VALUE "Longer string value 789"

    /* standard strdup */
    rc = sr_mem_edit_string_va_wrapper(NULL, &string, STRING_TEMPLATE, 123);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, STRING_VALUE));
    rc = sr_mem_edit_string_va_wrapper(NULL, &string, SHORTER_STRING_TEMPLATE, 456);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, SHORTER_STRING_VALUE));
    rc = sr_mem_edit_string_va_wrapper(NULL, &string, LONGER_STRING_TEMPLATE, 789);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, LONGER_STRING_VALUE));
    free(string);
    string = NULL;

    rc = sr_mem_new(0, &sr_mem);
    assert_int_equal(SR_ERR_OK, rc);

    /* sysrepo "strdup" */
    rc = sr_mem_edit_string_va_wrapper(sr_mem, &string, STRING_TEMPLATE, 123);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    size = strlen(STRING_VALUE) + 1;
    assert_int_equal(0, strcmp(string, STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem, string);

    /* overwrite */
    rc = sr_mem_edit_string_va_wrapper(sr_mem, &string, SHORTER_STRING_TEMPLATE, 456);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    assert_int_equal(0, strcmp(string, SHORTER_STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem, string);

    /* realloc */
    rc = sr_mem_edit_string_va_wrapper(sr_mem, &string, LONGER_STRING_TEMPLATE, 789);
    assert_int_equal(SR_ERR_OK, rc);
    assert_non_null(string);
    size += strlen(LONGER_STRING_VALUE) + 1;
    assert_int_equal(0, strcmp(string, LONGER_STRING_VALUE));
    check_num_of_mem_blocks(sr_mem, 3);
    check_mem_block_usage(sr_mem, 0, 0, size);
    assert_ptr_equal(sr_mem->cursor, sr_mem->mem_blocks->first);
    assert_int_equal(sr_mem->used_total, sr_mem->peak);
    assert_int_equal(size, sr_mem->used_total);
    assert_int_equal(0, sr_mem->obj_count);
    assert_int_equal(size_total, sr_mem->size_total);
    mem_block = get_mem_block(sr_mem, 0);
    assert_ptr_equal(mem_block->mem + strlen(STRING_VALUE) + 1, string);

    sr_mem_free(sr_mem);

#undef STRING_TEMPLATE
#undef STRING_VALUE
#undef SHORTER_STRING_TEMPLATE
#undef SHORTER_STRING_VALUE
#undef LONGER_STRING_TEMPLATE
#undef LONGER_STRING_VALUE
}

int
main() {
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(sr_mem_new_test),
        cmocka_unit_test(sr_malloc_test),
        cmocka_unit_test(sr_calloc_test),
        cmocka_unit_test(sr_mem_snapshot_test),
        cmocka_unit_test(sr_mem_edit_string_test),
        cmocka_unit_test(sr_mem_edit_string_va_test),
        cmocka_unit_test(sr_realloc_test),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
