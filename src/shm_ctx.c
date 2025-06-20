/**
 * @file shm_ctx.c
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief ctx SHM routines
 *
 * @copyright
 * Copyright (c) 2018 - 2025 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2025 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "shm_ctx.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "config.h"
#include "log.h"
#include "ly_wrap.h"
#include "sysrepo.h"

sr_error_info_t *
sr_shmctx_print_context(sr_shm_t *shm, const struct ly_ctx *ctx)
{
    sr_error_info_t *err_info = NULL;
    int ctx_size, fd = -1;
    void *mem = NULL, *mem_end;
    char *shm_name = NULL;

    if ((err_info = sr_path_ctx_shm(&shm_name))) {
        goto cleanup;
    }

    fd = sr_open(shm_name, O_RDWR | O_CREAT | O_TRUNC, SR_SHM_PERM);
    if (fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open ctx shared memory (%s).", strerror(errno));
        goto cleanup;
    }

    /* get the size of the compiled context */
    ctx_size = ly_ctx_compiled_size(ctx);

    /* truncate the shared memory to the size of the printed context */
    if (ftruncate(fd, ctx_size)) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to truncate the printed context (%s).", strerror(errno));
        goto cleanup;
    }

    /* unmap to avoid collision */
    if (shm->addr) {
        munmap(shm->addr, shm->size);
        shm->addr = NULL;
        shm->size = 0;
    }

    /* allocate memory for the printed context */
    mem = mmap(SR_PRINTED_LYCTX_ADDRESS, ctx_size, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED_NOREPLACE, fd, 0);
    if (mem == MAP_FAILED) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to map the printed context (%s).", strerror(errno));
        mem = NULL;
        goto cleanup;
    }

    /* print the context into the allocated memory */
    if (ly_ctx_compiled_print(ctx, mem, &mem_end)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to print the context.");
        goto cleanup;
    }
    assert(((char *)mem_end - (char *)mem) == ctx_size);

cleanup:
    if (err_info && shm_name) {
        unlink(shm_name);
    }
    free(shm_name);
    if (fd > -1) {
        close(fd);
    }
    if (mem) {
        munmap(mem, ctx_size);
    }
    return err_info;
}

sr_error_info_t *
sr_shmctx_get_printed_context(sr_shm_t *shm, struct ly_ctx **ctx)
{
    sr_error_info_t *err_info;
    size_t shm_file_size = 0;
    char *shm_name = NULL;

    *ctx = NULL;

    if ((err_info = sr_path_ctx_shm(&shm_name))) {
        goto cleanup;
    }

    /* check if the file exists */
    if (!sr_file_exists(shm_name)) {
        /* no context stored */
        goto cleanup;
    }

    /* open the shared memory if not open */
    if (shm->fd == -1) {
        shm->fd = sr_open(shm_name, O_RDONLY, SR_SHM_PERM);
        if (shm->fd == -1) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open mod shared memory (%s).", strerror(errno));
            goto cleanup;
        }
    }

    /* read the new shm size if not set */
    if ((err_info = sr_file_get_size(shm->fd, &shm_file_size))) {
        return err_info;
    }

    if (shm_file_size != shm->size) {
        if (shm->addr) {
            munmap(shm->addr, shm->size);
            shm->addr = NULL;
            shm->size = 0;
        }

        shm->addr = mmap(SR_PRINTED_LYCTX_ADDRESS, shm_file_size, PROT_READ, MAP_PRIVATE | MAP_FIXED_NOREPLACE, shm->fd, 0);
        if (shm->addr == MAP_FAILED) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to map the printed context (%s).", strerror(errno));
            shm->addr = NULL;
            goto cleanup;
        }
        shm->size = shm_file_size;
    }

    /* get the printed context */
    if (ly_ctx_new_printed(shm->addr, ctx)) {
        sr_errinfo_new(&err_info, SR_ERR_INTERNAL, "Failed to parse the printed context.");
        goto cleanup;
    }

cleanup:
    free(shm_name);
    return err_info;
}
