/**
 * @file srpd_common.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief common functions for sysrepo-plugind
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

#define _GNU_SOURCE

#include "srpd_common.h"

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "bin_common.h"
#include "srpd_aging.h"
#include "sysrepo.h"

/**
 * @brief An array of internal plugins
 */
struct srpd_int_plugin_s int_plugins[1] = {{srpd_aging_init_cb, srpd_aging_cleanup_cb, "srpd_aging"}};

void
srpd_error_print(int sr_error, const char *format, ...)
{
    va_list ap;
    char msg[2048];

    if (!sr_error) {
        sprintf(msg, "sysrepo-plugind error: %s\n", format);
    } else {
        sprintf(msg, "sysrepo-plugind error: %s (%s)\n", format, sr_strerror(sr_error));
    }

    va_start(ap, format);
    vfprintf(stderr, msg, ap);
    va_end(ap);
}

/* from src/common.c */
int
srpd_mkpath(const char *path, mode_t mode)
{
    char *p, *dup;

    dup = strdup(path);
    for (p = strchr(dup + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (mkdir(dup, mode) == -1) {
            if (errno != EEXIST) {
                *p = '/';
                free(dup);
                return -1;
            }
        }
        *p = '/';
    }
    free(dup);

    if (mkdir(path, mode) == -1) {
        if (errno != EEXIST) {
            return -1;
        }
    }

    return 0;
}

size_t
srpd_path_len_no_ext(const char *path)
{
    char *dot;

    dot = strrchr(path, '.');

    return dot ? (size_t)(dot - path) : strlen(path);
}

int
srpd_exec(const char *cmd, uint32_t num_of_args, ...)
{
    pid_t pid;
    int ret, rc = 0;
    char **args = NULL;
    uint32_t i;
    va_list ap;

    va_start(ap, num_of_args);

    pid = fork();
    if (pid == 0) {
        for (i = 0; i < num_of_args; ++i) {
            args = realloc(args, (i + 2) * sizeof *args);
            args[i] = va_arg(ap, char *);
        }
        args[i] = NULL;

        if (execv(cmd, args) == -1) {
            srpd_error_print(0, "Execv failed: (%s).", strerror(errno));
            exit(1);
        }
    } else if (pid == -1) {
        srpd_error_print(0, "Fork failed: (%s).", strerror(errno));
        rc = 1;
        goto cleanup;
    }

    if (waitpid(pid, &ret, 0) == -1) {
        srpd_error_print(0, "Waitpid failed (%s).", strerror(errno));
        rc = 1;
        goto cleanup;
    }
    if (!WIFEXITED(ret)) {
        if (WIFSIGNALED(ret)) {
            srpd_error_print(0, "Child has been terminated by a signal no: %d.", WTERMSIG(ret));
        } else {
            srpd_error_print(0, "Child has not terminated correctly.");
        }
        rc = 1;
        goto cleanup;
    }

cleanup:
    va_end(ap);
    return rc;
}

int
srpd_get_plugins_dir(const char **plugins_dir)
{
    /* get plugins dir from environment variable, or use default one */
    *plugins_dir = getenv("SRPD_PLUGINS_PATH");
    if (!*plugins_dir) {
        *plugins_dir = SRPD_PLG_PATH;
    }

    /* create the directory if it does not exist */
    if (access(*plugins_dir, F_OK) == -1) {
        if (errno != ENOENT) {
            srpd_error_print(0, "Checking plugins dir existence failed (%s).", strerror(errno));
            return -1;
        }
        if (srpd_mkpath(*plugins_dir, 00777) == -1) {
            srpd_error_print(0, "Creating plugins dir \"%s\" failed (%s).", *plugins_dir, strerror(errno));
            return -1;
        }
    }

    return 0;
}

void
srpd_swap(struct srpd_plugin_s *a, struct srpd_plugin_s *b)
{
    struct srpd_plugin_s tmp;

    if (a == b) {
        return;
    }

    tmp = *a;
    *a = *b;
    *b = tmp;
}

static int
srpd_plugin_names_cmp(const struct srpd_plugin_s *plugin, const char *str2)
{
    /* str1 does not have the filename extension */
    const char *str1 = plugin->plugin_name;
    size_t n;

    if (str1 == str2) {
        return 0;
    }

    n = srpd_path_len_no_ext(str2);

    return (strlen(str1) == n) ? strncmp(str1, str2, n) : -1;
}

int
srpd_sort_plugins(sr_session_ctx_t *sess, struct srpd_plugin_s *plugins, int plugin_count)
{
    const char *xpath = "/sysrepo-plugind:sysrepo-plugind/plugin-order/plugin";
    sr_val_t *values;
    size_t i, value_cnt;
    int r, j, ordered_part = 0;

    if ((r = sr_get_items(sess, xpath, 0, 0, &values, &value_cnt))) {
        srpd_error_print(r, "Getting \"%s\" items failed.", xpath);
        return r;
    }

    for (i = 0; i < value_cnt; ++i) {
        for (j = ordered_part; j < plugin_count; ++j) {
            if (!srpd_plugin_names_cmp(&plugins[j], values[i].data.string_val)) {
                srpd_swap(&plugins[ordered_part], &plugins[j]);
                ++ordered_part;
            }
        }
    }
    /* if values[i] wasn't found in plugins, it doesn't matter, it'll just be ignored. */

    sr_free_values(values, value_cnt);
    return SR_ERR_OK;
}
