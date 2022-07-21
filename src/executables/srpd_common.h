/**
 * @file srpd_common.h
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief header of common functions for sysrepo-plugind
 *
 * @copyright
 * Copyright (c) 2018 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#include "sysrepo_types.h"

#include <sys/types.h>

struct srpd_plugin_s {
    void *handle;
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    void *private_data;
    char *plugin_name;
    int initialized;
};

void srpd_error_print(int sr_error, const char *format, ...);

int srpd_mkpath(const char *path, mode_t mode);

size_t srpd_path_len_no_ext(const char *path);

int srpd_exec(const char *cmd, uint32_t num_of_args, ...);

int srpd_get_plugins_dir(const char **plugins_dir);

void srpd_swap(struct srpd_plugin_s *a, struct srpd_plugin_s *b);

int srpd_sort_plugins(sr_session_ctx_t *sess, struct srpd_plugin_s *plugins, int plugin_count);

