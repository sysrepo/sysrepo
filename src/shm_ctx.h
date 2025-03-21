/**
 * @file shm_ctx.h
 * @author Roman Janota <Roman.Janota@cesnet.cz>
 * @brief header for ctx SHM routines
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

#ifndef _SHM_CTX_H
#define _SHM_CTX_H

#include "shm_types.h"
#include "sysrepo_types.h"

sr_error_info_t *sr_shmctx_print_context(sr_shm_t *shm, const struct ly_ctx *ctx);

sr_error_info_t *sr_shmctx_get_printed_context(sr_shm_t *shm, struct ly_ctx **ctx);

#endif /* _SHM_CTX_H */
