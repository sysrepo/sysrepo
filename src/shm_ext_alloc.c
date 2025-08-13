/**
 * @file shm_ext_alloc.c
 * @author Irfan Mohammad
 * @brief ext SHM allocator routines
 *
 * @copyright
 * Copyright (c) 2025
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "log.h"
#include "shm_ext.h"
#include "shm_ext_alloc.h"

#include <assert.h>
#include <errno.h>
#include <sys/mman.h>

/* Macro for table size from number of blocks. */
#define SR_SHMEXT_TABLE_SIZE(num_blocks) (sizeof(sr_shmext_table_t) + (num_blocks) * sizeof(sr_shmext_block_usage_t))

/* Macro for Ext SHM size from number of blocks. */
#define SR_SHMEXT_SIZE_FROM_BLOCKS(num_blocks) (SR_SHMEXT_TABLE_SIZE(num_blocks) + ((num_blocks) * SR_SHMEXT_BLOCK_SIZE))

/* Macro for total number of blocks in Ext SHM determined from the SHM size. */
#define SR_SHMEXT_BLOCK_COUNT(shm_size) (((shm_size) - sizeof(sr_shmext_table_t)) / (SR_SHMEXT_BLOCK_SIZE + sizeof(sr_shmext_block_usage_t)))

typedef struct {
    uint8_t data[SR_SHMEXT_BLOCK_SIZE];
} sr_shmext_block_t;

sr_shmext_table_t *
sr_shmext_get_table(const sr_shm_t *shm)
{
    sr_shmext_table_t *table = NULL;
    /* first learn the Ext SHM data partition size */
    uint32_t data_size = SR_SHMEXT_BLOCK_COUNT(shm->size) * SR_SHMEXT_BLOCK_SIZE;

    /* allocation table is located beyond the data partition */
    table = (sr_shmext_table_t *)(shm->addr + data_size);

    if (table->block_count) {
        assert((table->magic == SR_SHMEXT_TABLE_MAGIC) && (table->block_count >= ATOMIC_LOAD_RELAXED(table->use_count)));
    } else {
        assert(!ATOMIC_LOAD_RELAXED(table->use_count) && !table->magic && !table->block_count);
    }

    return table;
}

sr_error_info_t *
sr_shmext_open(sr_shm_t *shm, int zero)
{
    sr_error_info_t *err_info = NULL;
    char *shm_name = NULL;
    sr_shmext_table_t *table;
    uint32_t size = SR_SHMEXT_SIZE_FROM_BLOCKS(SR_SHMEXT_INIT_BLOCK_COUNT);

    err_info = sr_path_ext_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    shm->fd = sr_open(shm_name, O_RDWR | O_CREAT, SR_SHM_PERM);
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open ext shared memory (%s).", strerror(errno));
        goto cleanup;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? size : 0))) {
        goto cleanup;
    }

    if (zero) {
        memset(shm->addr, 0, shm->size);
        table = sr_shmext_get_table(shm);
        table->magic = SR_SHMEXT_TABLE_MAGIC;
        table->block_count = SR_SHMEXT_BLOCK_COUNT(shm->size);
        if ((err_info = sr_mutex_init(&table->lock, 1))) {
            goto cleanup;
        }
        /* reserve the zeroth block, so we can use a '0' offset as an invalid/NULL offset */
        ATOMIC_STORE_RELAXED(table->used[0], 1);
        ATOMIC_STORE_RELAXED(table->use_count, 1);

        /* check that ext SHM is properly initialized */
        assert(shm->size == size);
        assert(table->block_count == SR_SHMEXT_INIT_BLOCK_COUNT);
    }

cleanup:
    if (err_info) {
        sr_shm_clear(shm);
    }

    return err_info;
}

uint32_t
sr_shmext_shrinkable(const sr_shm_t *shm)
{
    sr_shmext_table_t *table = sr_shmext_get_table(shm);
    uint32_t i, free_blocks = 0;

    /* check if there is at least twice SR_SHMEXT_GROW_BLOCKS free space */
    if (table->block_count - ATOMIC_LOAD_RELAXED(table->use_count) < 2 * SR_SHMEXT_GROW_BLOCKS) {
        return 0;
    }

    /* check if the free space is at the tail-end of the SHM */
    for (i = table->block_count; i > 0; i--) {
        if (ATOMIC_LOAD_RELAXED(table->used[i - 1])) {
            break;
        }
        free_blocks++;
    }

    /* leave SR_SHMEXT_GROW_BLOCKS available for future use */
    free_blocks = (free_blocks > 2 * SR_SHMEXT_GROW_BLOCKS) ? (free_blocks - SR_SHMEXT_GROW_BLOCKS) : 0;

    return free_blocks;
}

void
sr_shmext_shrink(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_shmext_table_t *table;
    off_t prev_table_offset;
    uint32_t prev_block_count, new_block_count, prev_shm_size, new_shm_size, del_blocks;

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        /* lock unavailable at this time, can always retry */
        sr_errinfo_free(&err_info);
        return;
    }

    /* learn how many blocks can be deleted with WRITE lock */
    if (!(del_blocks = sr_shmext_shrinkable(&conn->ext_shm))) {
        goto unlock;
    }

    /* remember previous table */
    table = sr_shmext_get_table(&conn->ext_shm);
    prev_table_offset = (char *)table - conn->ext_shm.addr;
    prev_block_count = SR_SHMEXT_BLOCK_COUNT(conn->ext_shm.size);
    prev_shm_size = conn->ext_shm.size;

    /* change the size */
    new_block_count = prev_block_count - del_blocks;
    new_shm_size = SR_SHMEXT_SIZE_FROM_BLOCKS(new_block_count);

    conn->ext_shm.size = new_shm_size;

    /* Ext SHM shrunk to [data + table + free_space] from [data + free_space + old_table] */
    /* locate the new table */
    table = sr_shmext_get_table(&conn->ext_shm);

    /* move the previous table to new location and update block_count */
    memmove(table, conn->ext_shm.addr + prev_table_offset, SR_SHMEXT_TABLE_SIZE(new_block_count));
    table->block_count = new_block_count;

    /* set the Ext SHM size back, to avoid leaving it in an inconsistent state */
    conn->ext_shm.size = prev_shm_size;

    if ((err_info = sr_shm_remap(&conn->ext_shm, new_shm_size))) {
        sr_errinfo_free(&err_info);
        return;
    }

    /* get the table again after remap */
    table = sr_shmext_get_table(&conn->ext_shm);

    /* sanity checks */
    assert(table->block_count == SR_SHMEXT_BLOCK_COUNT(conn->ext_shm.size));
    assert(SR_SHMEXT_SIZE_FROM_BLOCKS(table->block_count) == conn->ext_shm.size);

unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);
}

static sr_error_info_t *
sr_shmext_grow(sr_conn_ctx_t *conn, size_t addl_blocks)
{
    sr_error_info_t *err_info = NULL;
    sr_shmext_table_t *table;
    off_t prev_table_offset, table_offset;
    uint32_t prev_block_count, prev_shm_size, block_count;

    /* remember previous table */
    table = sr_shmext_get_table(&conn->ext_shm);
    prev_table_offset = (char *)table - conn->ext_shm.addr;
    prev_shm_size = conn->ext_shm.size;
    prev_block_count = SR_SHMEXT_BLOCK_COUNT(prev_shm_size);
    block_count = prev_block_count + addl_blocks;

    /* add more space in ext SHM size */
    if ((err_info = sr_shm_remap(&conn->ext_shm, SR_SHMEXT_SIZE_FROM_BLOCKS(block_count)))) {
        return err_info;
    }

    /* Ext SHM grown from [data + table] to [data + table + new_space + new_table] */
    /* new allocation table is located beyond the new data partition */
    table_offset = block_count * SR_SHMEXT_BLOCK_SIZE;
    table = (sr_shmext_table_t *)(conn->ext_shm.addr + table_offset);

    /* move the previous table to new location and update block_count */
    memmove(table, conn->ext_shm.addr + prev_table_offset, SR_SHMEXT_TABLE_SIZE(prev_block_count));
    table->block_count = block_count;

    /* zero the previous table and new space */
    memset(conn->ext_shm.addr + prev_table_offset, 0, table_offset - prev_table_offset);

    /* sanity checks */
    assert(table->block_count == SR_SHMEXT_BLOCK_COUNT(conn->ext_shm.size));
    assert(SR_SHMEXT_SIZE_FROM_BLOCKS(table->block_count) == conn->ext_shm.size);

    return NULL;
}

/**
 * @brief release the previously allocated region starting at offset from the Ext SHM.
 * This zeroes both the region and the used field in the table for the released blocks.
 *
 * @param count if non-zero, only release count blocks at the end, and adjust the use count.
 * */
void
sr_shmext_release(const sr_shm_t *shm, off_t offset, uint32_t count)
{
    sr_shmext_table_t *table = sr_shmext_get_table(shm);
    sr_shmext_block_t *block = (sr_shmext_block_t *)shm->addr;
    uint32_t i, free_idx, start_block_idx = offset / SR_SHMEXT_BLOCK_SIZE;
    sr_shmext_block_usage_t used_blocks = table->used[start_block_idx];

    if (!offset) {
        /* 0 offset means never allocated! */
        return;
    }

    count = count ? count : used_blocks;

    assert(count && (count <= used_blocks));

    free_idx = start_block_idx + used_blocks - count;

    /* clear released blocks of any data */
    memset(block + free_idx, 0, count * sizeof(*block));

    /* mark the blocks as free in the usage table */
    for (i = free_idx; i < start_block_idx + used_blocks; i++) {
        /* memory order release is required to prevent reordering with memset above. */
        ATOMIC_STORE_RELEASE(table->used[i], 0u);
    }

    /* Only reduce the used field of the start_block if we didn't release it all.
     * If we had already set this to zero, another thread may have already taken it.
     * and we don't want to corrupt the table. */
    if (count < used_blocks) {
        ATOMIC_STORE_RELEASE(table->used[start_block_idx], used_blocks - count);
    }
    ATOMIC_SUB_RELAXED(table->use_count, count);
}

void
sr_shmext_realloc_del(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count, size_t item_size, uint32_t del_idx,
        size_t dyn_attr_size, off_t dyn_attr_off)
{
    uint32_t num_blocks = SR_SHMEXT_ALIGNED_BLOCKS(item_size * (*shm_count));
    uint32_t new_blocks = SR_SHMEXT_ALIGNED_BLOCKS(item_size * (*shm_count - 1));
    uint32_t free_blocks = num_blocks - new_blocks;

    assert((!dyn_attr_size && !dyn_attr_off) || (dyn_attr_size && dyn_attr_off));
    assert(shm_count && *shm_count);

    /*
     * perform the removal
     */
    --(*shm_count);
    if (!*shm_count) {
        /* the only item left is being removed */
        sr_shmext_release(shm_ext, *shm_array_off, 0);
        *shm_array_off = 0;
    } else if (del_idx < *shm_count) {
        /* move all following items, we may need to keep the order intact */
        memmove((shm_ext->addr + *shm_array_off) + (del_idx * item_size),
                (shm_ext->addr + *shm_array_off) + ((del_idx + 1) * item_size),
                (*shm_count - del_idx) * item_size);

        /* release any freed up blocks */
        if (free_blocks) {
            sr_shmext_release(shm_ext, *shm_array_off, free_blocks);
        }
    }

    /* remove the dynamic attribute if any */
    if (dyn_attr_size) {
        sr_shmext_release(shm_ext, dyn_attr_off, 0);
    }
}

/**
 * @brief Try to reserve a chunk of `count` blocks, starting at offset
 *
 * @return 1 if chunk is reserved successfully, 0 if chunk is unavailable.
 * */
static int
sr_shmext_try_reserve(sr_shmext_table_t *table, uint32_t *start, uint32_t count)
{
    sr_error_info_t *err_info = NULL;
    int success = 0;
    sr_shmext_block_usage_t expected = 0u;
    off_t i, j, end = *start + count;

    assert(table && start && count);

    if (table->block_count < end) {
        return 0;
    }

    /* check if any blocks between start and end are already in-use */
    for (i = *start; i < end; i++) {
        if (ATOMIC_LOAD_RELAXED(table->used[i])) {
            /* update the starting index to search a next time */
            *start = i + 1;
            return 0;
        }
    }

    /* chunk is available, obtain a table lock and reserve it */
    if ((err_info = sr_mlock(&table->lock, SR_EXT_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        return 0;
    }

    for (i = *start; i < end; i++) {
        expected = 0u;
        /* compare exchange to certainly set it by this thread */
        ATOMIC_COMPARE_EXCHANGE_RELAXED(table->used[i], expected, 1u, success);
        if (!success) {
            break;
        }
    }

    /* reserved all blocks */
    if (success) {
        ATOMIC_STORE_RELAXED(table->used[*start], count);
        ATOMIC_ADD_RELAXED(table->use_count, count);
        goto unlock;
    }

    /* undo the reserved blocks on failure, safe because only this thread set it. */
    for (j = *start; j < i; j++) {
        ATOMIC_STORE_RELAXED(table->used[j], 0u);
    }

    /* we have checked the block from *start to i, and it is no longer available */
    *start = i + 1;

unlock:
    sr_munlock(&table->lock);

    return success;
}

/**
 * @brief Find an offset of a chunk of "available" blocks, of length len
 *
 * */
static void
sr_shmext_alloc_helper(const sr_shm_t *shm, uint32_t len, off_t *offset)
{
    uint32_t i, used = 0;
    uint32_t num_blocks = SR_SHMEXT_ALIGNED_BLOCKS(len);
    sr_shmext_table_t *table = sr_shmext_get_table(shm);

    *offset = 0;

    for (i = 0; (i + num_blocks) <= table->block_count; i += used) {
        if ((used = ATOMIC_LOAD_RELAXED(table->used[i]))) {
            continue;
        }
        if (sr_shmext_try_reserve(table, &i, num_blocks)) {
            *offset = i * SR_SHMEXT_BLOCK_SIZE;
            break;
        }
    }
}

/*
 * @brief Allocates a chunk of len bytes in the Ext SHM.
 * Must be called with READ ext_lock and remap_lock held.
 * ext_lock and remap_lock are unlocked if an error occurs!
 *
 * @param[in] conn Connection to use.
 * @param[in] length Length in bytes to allocate.
 * @param[out] offset The offset in Ext SHM allocated on success.
 *
 * @return NULL on success, err_info if an error occurs.
 */
sr_error_info_t *
sr_shmext_alloc(sr_conn_ctx_t *conn, uint32_t length, off_t *offset)
{
    sr_error_info_t *err_info = NULL;
    size_t num_blocks;

    assert(offset);

    if (!length) {
        return NULL;
    }

    sr_shmext_alloc_helper(&conn->ext_shm, length, offset);
    if (*offset) {
        /* success, we found a place */
        return NULL;
    }

    /* did not find a spot, grow the SHM with a WRITE lock */

    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        return err_info;
    }

    num_blocks = SR_SHMEXT_ALIGNED_BLOCKS(length) > SR_SHMEXT_GROW_BLOCKS ?
            SR_SHMEXT_ALIGNED_BLOCKS(length) : SR_SHMEXT_GROW_BLOCKS;

    /* grow the Ext SHM */
    if ((err_info = sr_shmext_grow(conn, num_blocks))) {
        goto err_unlock;
    }

    /* try allocation again, should succeed as we have just grown the Ext SHM, and we hold WRITE locks */
    sr_shmext_alloc_helper(&conn->ext_shm, length, offset);
    SR_CHECK_INT_GOTO(!*offset, err_info, err_unlock);

    /* downgrade to a READ LOCK */
    if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ,
            conn->cid, __func__, NULL, NULL))) {
        goto err_unlock;
    }

    if ((err_info = sr_rwrelock(&SR_CONN_MAIN_SHM(conn)->ext_lock, SR_EXT_LOCK_TIMEOUT, SR_LOCK_READ,
            conn->cid, __func__, NULL, NULL))) {
        /* unlock the held locks */
        sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        sr_rwunlock(&SR_CONN_MAIN_SHM(conn)->ext_lock, SR_EXT_LOCK_TIMEOUT, SR_LOCK_WRITE,
                conn->cid, __func__);
    }

    return err_info;
err_unlock:
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_realloc_add(sr_conn_ctx_t *conn, off_t *shm_array_off, uint32_t *shm_count, int in_ext_shm,
        size_t item_size, int64_t add_idx, void **new_item, size_t dyn_attr_size, off_t *dyn_attr_off)
{
    sr_error_info_t *err_info = NULL;
    sr_shmext_table_t *table = sr_shmext_get_table(&conn->ext_shm);
    uint32_t old_array_size = item_size * (*shm_count);
    uint32_t new_array_size = old_array_size + item_size;
    uint32_t alignment = SR_SHMEXT_BLOCK_SIZE - (old_array_size % SR_SHMEXT_BLOCK_SIZE);
    uint32_t free_space_in_last_blk = alignment % SR_SHMEXT_BLOCK_SIZE;

    uint32_t addl_space_needed = item_size - free_space_in_last_blk;
    uint32_t addl_blocks = SR_SHMEXT_ALIGNED_BLOCKS(addl_space_needed);
    uint32_t adj_block = SR_SHMEXT_ALIGNED_BLOCKS(*shm_array_off + old_array_size);
    uint32_t first_block = SR_SHMEXT_ALIGNED_BLOCKS(*shm_array_off);

    /* remember current SHM mapping address */
    const char *old_shm_addr = conn->ext_shm.addr;

    off_t old_offset = *shm_array_off;

    off_t new_offset = old_offset;

    /* if we already have some data, try to see if we can fit new data nearby */
    if (*shm_count) {
        /* we have the space needed in the current chunk itself, no more blocks are needed */
        if (item_size <= free_space_in_last_blk) {
            goto move_data;
        }

        /* we need additional blocks */
        /* are they available right next to us? */
        if (sr_shmext_try_reserve(table, &adj_block, addl_blocks)) {
            ATOMIC_ADD_RELAXED(table->used[first_block], addl_blocks);
            ATOMIC_STORE_RELAXED(table->used[adj_block], 1);
            goto move_data;
        }
    }

    /* find a new space large enough for new_array_size */
    if ((err_info = sr_shmext_alloc(conn, new_array_size, &new_offset))) {
        return err_info;
    }

    /* update our pointers after ext SHM was remapped */
    if (in_ext_shm) {
        shm_array_off = (off_t *)(conn->ext_shm.addr + (((char *)shm_array_off) - old_shm_addr));
        shm_count = (uint32_t *)(conn->ext_shm.addr + (((char *)shm_count) - old_shm_addr));
    }

    if (old_array_size) {
        /* relocate old array to the new_offset */
        memcpy(conn->ext_shm.addr + new_offset, conn->ext_shm.addr + old_offset, old_array_size);

        /* release the old data */
        sr_shmext_release(&conn->ext_shm, old_offset, 0);
    }

    *shm_array_off = new_offset;

move_data:
    /* move items right if necessary */
    if (*shm_count && (add_idx >= 0) && (add_idx < *shm_count)) {
        /* move all items add_idx and beyond, to add_idx+1, there are count - add_idx such items */
        memmove(conn->ext_shm.addr + new_offset + (add_idx + 1) * item_size,
                conn->ext_shm.addr + new_offset + (add_idx * item_size), (*shm_count - add_idx) * item_size);
    } else {
        add_idx = *shm_count;
    }

    /* insert the new element at add_idx */
    (*new_item) = (conn->ext_shm.addr + new_offset) + (add_idx * item_size);
    /* update array count */
    ++(*shm_count);

    if (!dyn_attr_size) {
        /* done here */
        return NULL;
    }

    /* remember current address */
    old_shm_addr = conn->ext_shm.addr;

    /* allocate space for dyn_attr */
    if ((err_info = sr_shmext_alloc(conn, dyn_attr_size, dyn_attr_off))) {
        /* previous allocation is incomplete, but this should really never happen */
        return err_info;
    }

    /* update our pointers after ext SHM was remapped */
    if (in_ext_shm) {
        shm_array_off = (off_t *)(conn->ext_shm.addr + (((char *)shm_array_off) - old_shm_addr));
        shm_count = (uint32_t *)(conn->ext_shm.addr + (((char *)shm_count) - old_shm_addr));
    }

    /* update new_item ptr again, SHM may have been remapped */
    (*new_item) = (conn->ext_shm.addr + *shm_array_off) + (add_idx * item_size);

    return NULL;
}
