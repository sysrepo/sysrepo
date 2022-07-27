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

extern struct srpd_int_plugin_s {
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    const char *plugin_name;
} int_plugins[1];

struct srpd_plugin_s {
    void *handle;
    srp_init_cb_t init_cb;
    srp_cleanup_cb_t cleanup_cb;
    void *private_data;
    char *plugin_name;
    int initialized;
};

/**
 * @brief Prints error message.
 *
 * @param[in] sr_error Type of error
 * @param[in] format Error message to be printed
 * @param[in] ... Additional parameters for message
 */
void srpd_error_print(int sr_error, const char *format, ...);

/**
 * @brief Creates path to dir or file.
 *
 * @param[in] path Path to be created.
 * @param[in] mode Access mode to the dir or file.
 * @return 0 on success.
 * @return -1 on failure.
 */
int srpd_mkpath(const char *path, mode_t mode);

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
 * @param[in] cmd Command to be executed.
 * @param[in] num_of_args Number of arguments given to function.
 * @param[in] ... Arguments of the command.
 * @return 0 on success.
 * @return 1 on failure.
 */
int srpd_exec(const char *cmd, uint32_t num_of_args, ...);

/**
 * @brief Retrieves plugin directory.
 *
 * @param[out] plugins_dir Out parameter for plugins directory
 * @return 0 on success.
 * @return -1 on failure.
 */
int srpd_get_plugins_dir(const char **plugins_dir);

/**
 * @brief Swaps contents of a and b.
 *
 * @param[in] a Parameter to be swapped
 * @param[in] b Parameter to be swapped
 */
void srpd_swap(struct srpd_plugin_s *a, struct srpd_plugin_s *b);

/**
 * @brief Sorts plugins.
 *
 * @param[in] sess Session to be used
 * @param[in] plugins Array of plugins to be sorted
 * @param[in] plugin_count Number of plugins within the array
 * @return SR_ERR_OK on success.
 */
int srpd_sort_plugins(sr_session_ctx_t *sess, struct srpd_plugin_s *plugins, int plugin_count);
