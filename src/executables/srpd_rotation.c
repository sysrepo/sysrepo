/**
 * @file srpd_rotation.c
 * @author Ondrej Kusnirik <Ondrej.Kusnirik@cesnet.cz>
 * @brief rotation utility for sysrepo-plugind
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

#include "compat.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>

#include <libyang/libyang.h>
#include <sysrepo.h>

#include "bin_common.h"
#include "config.h"
#include "srpd_common.h"

#define SRPD_PLUGIN_NAME "srpd_rotation"

/**
 * @brief Internal struct for rotation.
 *
 */
typedef struct {
    ATOMIC64_T rotation_time;
    ATOMIC_PTR_T output_folder;
    ATOMIC_T compress;
    ATOMIC64_T rotated_files_count;
    sr_subscription_ctx_t *subscr;
    pthread_t tid;
    ATOMIC_T running;
} srpd_rotation_data_t;

/**
 * @brief Get the path to notif folder.
 *
 * @return Path to notification folder.
 */
static char *
srpd_get_notif_path(void)
{
    char *path;

    if (SR_NOTIFICATION_PATH[0]) {
        path = strdup(SR_NOTIFICATION_PATH);
    } else {
        if (asprintf(&path, "%s/data/notif/", sr_get_repo_path()) == -1) {
            path = NULL;
        }
    }

    return path;
}

static int
srpd_get_rot_count_cb(sr_session_ctx_t *session, uint32_t sub_id, const char *module_name, const char *path,
        const char *request_xpath, uint32_t request_id, struct lyd_node **parent, void *private_data)
{
    int rc = 0;
    const struct ly_ctx *ctx;
    char value[21];
    srpd_rotation_data_t *data = (srpd_rotation_data_t *)private_data;

    (void)sub_id;
    (void)module_name;
    (void)path;
    (void)request_xpath;
    (void)request_id;

    sprintf(value, "%" PRIu64, ATOMIC_LOAD_RELAXED(data->rotated_files_count));
    ctx = sr_session_acquire_context(session);
    if ((rc = lyd_new_path(*parent, ctx, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/rotated-files-count",
            value, 0, NULL)) != LY_SUCCESS) {
        goto cleanup;
    }

cleanup:
    sr_session_release_context(session);
    return rc;
}

/**
 * @brief Checks whether the format of the file name
 * matches std format of notification file.
 *
 * @param[in] file_name File name to be checked.
 * @param[out] file_time1 First derived time from the file name.
 * @param[out] file_time2 Second derived time from the file name.
 * @return 0 on success.
 * @return 1 on failure.
 */
static int
srpd_format_check(const char *file_name, time_t *file_time1, time_t *file_time2)
{
    char *x = NULL, *endptr = NULL;
    time_t time1, time2;
    char buf[7];

    memset(buf, '\0', 7);

    if (file_name == NULL) {
        return EXIT_FAILURE;
    }
    x = strchr(file_name, '.');
    if (x == NULL) {
        return EXIT_FAILURE;
    }
    strncpy(buf, x + 1, 6);
    if (strcmp(buf, "notif.")) {
        return EXIT_FAILURE;
    }
    x = strchr(x + 1, '.');
    time1 = strtoul(x + 1, &endptr, 10);
    if (!strcmp(endptr, x + 1)) {
        return EXIT_FAILURE;
    }
    x = strchr(x + 1, '-');
    if (x == NULL) {
        return EXIT_FAILURE;
    }
    time2 = strtoul(x + 1, &endptr, 10);
    if (!strcmp(endptr, x + 1)) {
        return EXIT_FAILURE;
    }

    if (file_time1 != NULL) {
        *file_time1 = time1;
    }
    if (file_time2 != NULL) {
        *file_time2 = time2;
    }
    return 0;
}

static void *
srpd_rotation_loop(void *arg)
{
    int rc = 0;
    DIR *d = NULL;
    struct dirent *dir = NULL;
    time_t current_time, file_time2 = 0;
    srpd_rotation_data_t *data = (srpd_rotation_data_t *)arg;
    char *arg1 = NULL, *arg2 = NULL, *remove_str = NULL, *notif_dir_name = NULL;

    notif_dir_name = srpd_get_notif_path();
    if (!notif_dir_name) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Notif directory is NULL.");
        goto cleanup;
    }
    if (srpd_mkpath((char *)ATOMIC_PTR_LOAD_RELAXED(data->output_folder), 0777, NULL) == -1) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Archive directory could not be created");
        goto cleanup;
    }

    for ( ; ATOMIC_LOAD_RELAXED(data->running); sleep(1)) {

        /* remember current time */
        time(&current_time);

        /* open directory */
        d = opendir(notif_dir_name);
        if (!d) {
            continue;
        }

        /* read whole directory */
        while ((dir = readdir(d)) && ATOMIC_LOAD_RELAXED(data->running)) {

            /* skip current and parent directories */
            if (!strcmp(dir->d_name, ".") || !strcmp(dir->d_name, "..")) {
                continue;
            }

            /* check correct format of the file and retrieve file times */
            if (srpd_format_check(dir->d_name, NULL, &file_time2)) {
                continue;
            }

            /* check whether a file is older than configured time */
            if ((current_time >= (time_t)ATOMIC_LOAD_RELAXED(data->rotation_time)) &&
                    (file_time2 < (current_time - (time_t)ATOMIC_LOAD_RELAXED(data->rotation_time)))) {

                /* build compressing args */
                if (ATOMIC_LOAD_RELAXED(data->compress)) {
                    if (asprintf(&arg1, "%s%s.tar.gz", (char *)ATOMIC_PTR_LOAD_RELAXED(data->output_folder), dir->d_name) == -1) {
                        goto cleanup;
                    }

                    /* skip the leading slash */
                    if (asprintf(&arg2, "%s%s", notif_dir_name + 1, dir->d_name) == -1) {
                        goto cleanup;
                    }

                    /* compress a file with tar in output folder */
                    if ((rc = srpd_exec(SRPD_PLUGIN_NAME, SRPD_TAR_BINARY, 6, SRPD_TAR_BINARY, "-czf", arg1, "-C", "/", arg2))) {
                        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Compressing a file %s failed.", arg2);
                    } else {
                        ATOMIC_INC_RELAXED(data->rotated_files_count);

                        if (asprintf(&remove_str, "%s%s", notif_dir_name, dir->d_name) == -1) {
                            goto cleanup;
                        }

                        /* remove a file from notif folder */
                        if (remove(remove_str)) {
                            SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Removing a file %s failed.", remove_str);
                        }
                    }

                    /* build moving args */
                } else {
                    if (asprintf(&arg1, "%s%s", notif_dir_name, dir->d_name) == -1) {
                        goto cleanup;
                    }
                    if (asprintf(&arg2, "%s%s", (char *)ATOMIC_PTR_LOAD_RELAXED(data->output_folder), dir->d_name) == -1) {
                        goto cleanup;
                    }

                    /* move a file to the output folder */
                    if ((rc = rename(arg1, arg2)) == -1) {
                        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Moving a file %s failed.", arg1);
                    } else {
                        ATOMIC_INC_RELAXED(data->rotated_files_count);
                    }
                }

                /* reset commands for next folders */
                rc = 0;
                free(arg1);
                free(arg2);
                free(remove_str);
                arg1 = NULL;
                arg2 = NULL;
                remove_str = NULL;
            }
        }
        closedir(d);
        d = NULL;
    }

cleanup:
    free(arg1);
    free(arg2);
    free(remove_str);
    free(notif_dir_name);
    if (d) {
        closedir(d);
    }
    return NULL;
}

static int
srpd_rotation_change_cb(sr_session_ctx_t *session, uint32_t UNUSED(sub_id), const char *UNUSED(module_name),
        const char *UNUSED(xpath), sr_event_t UNUSED(event), uint32_t UNUSED(request_id), void *private_data)
{
    srpd_rotation_data_t *data = (srpd_rotation_data_t *)private_data;
    int rc = SR_ERR_OK, t_creat = 0;
    time_t time_value;
    sr_change_iter_t *iter = NULL;
    sr_change_oper_t oper;
    const struct lyd_node *node;
    char *temp = NULL, *dir_str = NULL, *time_unit = NULL;

    if ((rc = sr_get_changes_iter(session, "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/enabled//.",
            &iter))) {
        goto cleanup;
    }

    while (!(rc = sr_get_change_tree_next(session, iter, &oper, &node, NULL, NULL, NULL))) {
        if (!strcmp(node->schema->name, "enabled")) {
            if (oper == SR_OP_CREATED) {
                t_creat = 1;
            } else if (oper == SR_OP_DELETED) {
                ATOMIC_STORE_RELAXED(data->running, 0);
                if ((rc = pthread_join(data->tid, NULL))) {
                    SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "pthread_join failed (%s).", strerror(rc));
                }
                /* continue and free iter */
            }

        } else if (!strcmp(node->schema->name, "older-than")) {
            time_value = strtoul(lyd_get_value(node), &time_unit, 10);

            /* convert bigger units to days */
            switch (time_unit[0]) {
            case 'Y':           /* time in years */
                time_value *= 365;
                break;
            case 'M':           /* time in months */
                time_value *= 30;
                break;
            case 'W':           /* time in weeks */
                time_value *= 7;
                break;
            }

            /* convert days and smaller units to seconds */
            switch (time_unit[0]) {
            default:
            case 'D':           /* time in days */
                time_value *= 24;
            /* fallthrough */
            case 'h':           /* time in hours */
                time_value *= 60;
            /* fallthrough */
            case 'm':           /* time in minutes */
                time_value *= 60;
            /* fallthrough */
            case 's':           /* time in seconds */
                break;
            }

            ATOMIC_STORE_RELAXED(data->rotation_time, time_value);

        } else if (!strcmp(node->schema->name, "output-dir")) {
            /* safe update of the output_folder (srpd_rotation_loop() reads output_folder!) */
            temp = ATOMIC_PTR_LOAD_RELAXED(data->output_folder);

            /* check whether there is a '/' at the end to further append other strings */
            if (lyd_get_value(node)[strlen(lyd_get_value(node)) - 1] != '/') {
                rc = asprintf(&dir_str, "%s/", lyd_get_value(node));
            } else {
                rc = asprintf(&dir_str, "%s", lyd_get_value(node));
            }
            if (rc == -1) {
                SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "asprintf() failed (%s:%d) (%s)", __FILE__, __LINE__, strerror(errno));
                goto cleanup;
            }
            ATOMIC_PTR_STORE_RELAXED(data->output_folder, dir_str);
            free(temp);
            temp = NULL;

        } else if (!strcmp(node->schema->name, "compress")) {
            if (!strcmp(lyd_get_value(node), "true")) {
                ATOMIC_STORE_RELAXED(data->compress, 1);
            } else {
                ATOMIC_STORE_RELAXED(data->compress, 0);
            }
        }
    }

    /* check whether a thread should be created */
    if (t_creat) {
        assert(ATOMIC_PTR_LOAD_RELAXED(data->output_folder));
        ATOMIC_STORE_RELAXED(data->running, 1);
        if ((rc = pthread_create(&(data->tid), NULL, &srpd_rotation_loop, data))) {
            SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Pthread create failed (%s).", strerror(rc));
        }
        t_creat = 0;
    }

cleanup:
    free(temp);
    sr_free_change_iter(iter);
    return rc;
}

int
srpd_rotation_init_cb(sr_session_ctx_t *session, void **private_data)
{
    int rc = SR_ERR_OK;
    srpd_rotation_data_t *data = NULL;

    data = calloc(1, sizeof *data);
    if (!data) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Memory allocation failed (%s:%d).", __FILE__, __LINE__);
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    /* create notification rotation change subscription */
    if ((rc = sr_module_change_subscribe(session, "sysrepo-plugind", "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/enabled",
            srpd_rotation_change_cb, data, 0, SR_SUBSCR_ENABLED | SR_SUBSCR_DONE_ONLY, &data->subscr))) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Failed to subscribe (%s)", sr_strerror(rc));
        goto cleanup;
    }

    /* create notification rotation state data change subscription */
    if ((rc = sr_oper_get_subscribe(session, "sysrepo-plugind", "/sysrepo-plugind:sysrepo-plugind/notif-datastore/rotation/rotated-files-count",
            srpd_get_rot_count_cb, data, 0, &data->subscr))) {
        SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "Failed to subscribe (%s)", sr_strerror(rc));
        goto cleanup;
    }

cleanup:
    if (rc) {
        if (data) {
            sr_unsubscribe(data->subscr);
            free(data);
        }
    } else {
        *private_data = data;
    }
    return rc;
}

void
srpd_rotation_cleanup_cb(sr_session_ctx_t *UNUSED(session), void *private_data)
{
    srpd_rotation_data_t *data = private_data;
    int r;

    sr_unsubscribe(data->subscr);
    if (ATOMIC_LOAD_RELAXED(data->running)) {
        ATOMIC_STORE_RELAXED(data->running, 0);
        if ((r = pthread_join(data->tid, NULL))) {
            SRPLG_LOG_ERR(SRPD_PLUGIN_NAME, "pthread_join failed (%s).", strerror(r));
        }
    }
    free(ATOMIC_PTR_LOAD_RELAXED(data->output_folder));
    free(data);
}
