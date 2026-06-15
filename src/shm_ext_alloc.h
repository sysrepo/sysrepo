#include <stdint.h>

/* Macro for Number of blocks needed to store data_len in Ext SHM. */
#define SR_SHMEXT_ALIGNED_BLOCKS(data_len) (((data_len) + SR_SHMEXT_BLOCK_SIZE - 1) / SR_SHMEXT_BLOCK_SIZE)

/* Macro for length of data in Ext SHM including alignment. */
#define SR_SHMEXT_ALIGNED_LEN(data_len) (SR_SHMEXT_BLOCK_SIZE * SR_SHMEXT_ALIGNED_BLOCKS(data_len))

/* Magic 0x8ab1ba5e (Tabl base) to verify the table start location. */
#define SR_SHMEXT_TABLE_MAGIC 0x8AB1BA5E

typedef ATOMIC16_T sr_shmext_block_usage_t;

typedef struct {
    uint32_t magic;       /**< Magic 0x8AB1BA5E (table base). to verify the table */
    pthread_mutex_t lock; /**< Lock for reserving blocks in the table. */
    ATOMIC_T use_count;   /**< Number of blocks in-use. */
    uint32_t block_count; /**< Total number of blocks in the Ext SHM. */
    sr_shmext_block_usage_t used[]; /**< Block usage table. */
} sr_shmext_table_t;

/**
 * @brief Get the Ext SHM allocation table from the Ext SHM pointer.
 *
 * @param[in] shm Pointer to Ext SHM.
 * @return Pointer to the allocation table, calculated from the shm->size.
 */
sr_shmext_table_t *sr_shmext_get_table(const sr_shm_t *shm);

sr_error_info_t *sr_shmext_realloc_add(sr_conn_ctx_t *conn, off_t *shm_array_off, uint32_t *shm_count, int in_ext_shm,
        size_t item_size, int64_t add_idx, void **new_item, size_t dyn_attr_size, off_t *dyn_attr_off);

void sr_shmext_realloc_del(sr_shm_t *shm_ext, off_t *shm_array_off, uint32_t *shm_count, size_t item_size,
        uint32_t del_idx, size_t dyn_attr_size, off_t dyn_attr_off);

void sr_shmext_release(const sr_shm_t *shm, off_t offset, uint32_t count);

sr_error_info_t *sr_shmext_alloc(sr_conn_ctx_t *conn, uint32_t length, off_t *offset);

/**
 * @brief Check if there is significant contiguous free space at the tail end of the SHM, making Ext SHM shrinkable.
 *
 * @param[in] shm Pointer to Ext SHM.
 * @return Number of blocks to remove, if shrinkable, zero otherwise.
 */
uint32_t sr_shmext_shrinkable(const sr_shm_t *shm);

/**
 * @brief Shrink the Ext SHM so that no more than 2*SR_SHMEXT_GROW_BLOCKS is free at the tail-end.
 *
 * @param[in] conn Connection to use.
 */
void sr_shmext_shrink(sr_conn_ctx_t *conn);
