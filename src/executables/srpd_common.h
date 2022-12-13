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

#ifndef _SRPD_COMMON_H
#define _SRPD_COMMON_H

#include <sys/types.h>

#include "sysrepo_types.h"

struct srpd_int_plugin_s {
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    const char *plugin_name;
};

struct srpd_plugin_s {
    void *handle;
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    void *private_data;
    char *plugin_name;
    int initialized;
};

/**
 * @brief Creates path to dir or file.
 *
 * @param[in] path Path to be created.
 * @param[in] mode Access mode to the dir or file.
 * @param[out] err_dir Optional parameter for retrieving the
 * last dir/file which the mkpath failed to create.
 * Needs to be freed afterwards.
 * @return 0 on success.
 * @return -1 on failure.
 */
int srpd_mkpath(const char *path, mode_t mode, char **err_dir);

/**
 * @brief Returns length of path without extensions.
 *
 * @param[in] path Path to measure length on.
 * @return Length of path.
 */
size_t srpd_path_len_no_ext(const char *path);

/**
 * @brief Executes command given by @param cmd with arguments.
 * First argument of the command has to be the command.
 * See man ::execv(2).
 *
 * @param[in] plugin_name Name of the plugin.
 * @param[in] cmd Command to be executed.
 * @param[in] num_of_args Number of arguments given to function.
 * @param[in] ... Arguments of the command.
 * @return 0 on success.
 * @return -1 on failure.
 */
int srpd_exec(const char *plugin_name, const char *cmd, uint32_t num_of_args, ...);

/**
 * @brief Swaps contents of a and b.
 *
 * @param[in] a Parameter to be swapped.
 * @param[in] b Parameter to be swapped.
 */
void srpd_swap(struct srpd_plugin_s *a, struct srpd_plugin_s *b);

/**
 * @brief Sorts plugins.
 *
 * @param[in] sess Session to be used.
 * @param[in] plugins Array of plugins to be sorted.
 * @param[in] plugin_count Number of plugins within the array.
 * @param[in] plugin_name Name of the plugin.
 * @return SR_ERR_OK on success.
 */
int srpd_sort_plugins(sr_session_ctx_t *sess, struct srpd_plugin_s *plugins, int plugin_count, const char *plugin_name);

/*
 * plugins
 */

/**
 * @brief Internal rotation notification plugin ::srp_init_cb_t and ::srp_cleanup_cb_t callback.
 *
 */
int srpd_rotation_init_cb(sr_session_ctx_t *session, void **private_data);
void srpd_rotation_cleanup_cb(sr_session_ctx_t *session, void *private_data);

/**
 * @brief Internal oper poll diff plugin ::srp_init_cb_t and ::srp_cleanup_cb_t callback.
 *
 */
int srpd_oper_poll_diff_init_cb(sr_session_ctx_t *session, void **private_data);
void srpd_oper_poll_diff_cleanup_cb(sr_session_ctx_t *session, void *private_data);

#endif
