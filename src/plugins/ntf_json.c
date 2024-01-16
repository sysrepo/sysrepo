/**
 * @file ntf_json.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief internal JSON notifications plugin
 *
 * @copyright
 * Copyright (c) 2021 Deutsche Telekom AG.
 * Copyright (c) 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "compat.h"
#include "plugins_notification.h"

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common_json.h"
#include "sysrepo.h"

#define srpntf_name "JSON notif" /**< plugin name */

/**
 * @brief Write notification into fd using vector IO.
 *
 * @param[in] notif_json Notification in JSON format.
 * @param[in] notif_json_len Length of notification in JSON format.
 * @param[in] notif_ts Notification timestamp.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_writev_notif(int fd, const char *notif_json, uint32_t notif_json_len, const struct timespec *notif_ts)
{
    sr_error_info_t *err_info = NULL;
    struct iovec iov[3];

    /* timestamp */
    iov[0].iov_base = (void *)notif_ts;
    iov[0].iov_len = sizeof *notif_ts;

    /* notification length */
    iov[1].iov_base = &notif_json_len;
    iov[1].iov_len = sizeof notif_json_len;

    /* notification */
    iov[2].iov_base = (void *)notif_json;
    iov[2].iov_len = notif_json_len;

    /* write the vector */
    if ((err_info = srpjson_writev(srpntf_name, fd, iov, 3))) {
        return err_info;
    }

    /* fsync */
    if (fsync(fd) == -1) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Fsync failed (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

/**
 * @brief Read timestamp from a notification file.
 *
 * @param[in] notif_fd Notification file descriptor.
 * @param[out] notif_ts Notification timestamp, zeroed if EOF reached.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_read_ts(int notif_fd, struct timespec *notif_ts)
{
    memset(notif_ts, 0, sizeof *notif_ts);

    return srpjson_read(srpntf_name, notif_fd, notif_ts, sizeof *notif_ts);
}

/**
 * @brief Read notification from a notification file.
 *
 * @param[in] notif_fd Notification file descriptor.
 * @param[in] ly_ctx libyang context.
 * @param[out] notif Notification data tree.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_read_notif(int notif_fd, struct ly_ctx *ly_ctx, struct lyd_node **notif)
{
    sr_error_info_t *err_info = NULL;
    char *notif_json = NULL;
    struct ly_in *in = NULL;
    uint32_t notif_json_len;

    /* read the length */
    if ((err_info = srpjson_read(srpntf_name, notif_fd, &notif_json_len, sizeof notif_json_len))) {
        goto cleanup;
    }

    /* read the notification */
    notif_json = malloc(notif_json_len + 1);
    if (!notif_json) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
        goto cleanup;
    }

    if ((err_info = srpjson_read(srpntf_name, notif_fd, notif_json, notif_json_len))) {
        goto cleanup;
    }
    notif_json[notif_json_len] = '\0';

    /* parse the notification */
    ly_in_new_memory(notif_json, &in);
    if (lyd_parse_op(ly_ctx, NULL, in, LYD_JSON, LYD_TYPE_NOTIF_YANG, notif, NULL)) {
        err_info = srpjson_log_err_ly(srpntf_name, ly_ctx);
        goto cleanup;
    }

cleanup:
    free(notif_json);
    ly_in_free(in, 0);
    return err_info;
}

/**
 * @brief Skip a notification in a notification file.
 *
 * @param[in] notif_fd Notification file descriptor.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_skip_notif(int notif_fd)
{
    sr_error_info_t *err_info = NULL;
    uint32_t notif_json_len;

    /* read notification length */
    if ((err_info = srpjson_read(srpntf_name, notif_fd, &notif_json_len, sizeof notif_json_len))) {
        return err_info;
    }

    /* skip the notification */
    if (lseek(notif_fd, notif_json_len, SEEK_CUR) == -1) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Lseek failed (%s).", strerror(errno));
        return err_info;
    }

    return NULL;
}

/**
 * @brief Open notification replay file.
 *
 * @param[in] mod_name Module name.
 * @param[in] from_ts Earliest stored notification.
 * @param[in] to_ts Latest stored notification.
 * @param[in] flags Open flags to use.
 * @param[out] notif_fd Opened file descriptor.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_open_file(const char *mod_name, time_t from_ts, time_t to_ts, int flags, int *notif_fd)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    mode_t perm = SRPJSON_NOTIF_PERM;

    *notif_fd = -1;

    if ((err_info = srpjson_get_notif_path(srpntf_name, mod_name, from_ts, to_ts, &path))) {
        goto cleanup;
    }

    *notif_fd = srpjson_open(srpntf_name, path, flags, perm);
    if (*notif_fd == -1) {
        err_info = srpjson_open_error(srpntf_name, path);
        goto cleanup;
    }

    if ((flags & O_CREAT) && (flags & O_EXCL)) {
        SRPLG_LOG_INF(srpntf_name, "Replay file \"%s\" created.", strrchr(path, '/') + 1);
    }

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Find specific replay notification file:
 * - from_ts = 0; to_ts = 0 - find latest file
 * - from_ts > 0; to_ts = 0 - find file possibly containing no-earlier-than from_ts (replay start_time)
 * - from_ts > 0; to_ts > 0 - find next file after this one
 *
 * @param[in] mod_name Module name.
 * @param[in] from_ts Earliest stored notification.
 * @param[in] to_ts Latest stored notification.
 * @param[out] file_from_ts Found file earliest notification.
 * @param[out] file_to_ts Found file latest notification.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_find_file(const char *mod_name, time_t from_ts, time_t to_ts, time_t *file_from_ts, time_t *file_to_ts)
{
    sr_error_info_t *err_info = NULL;
    int pref_len;
    DIR *dir = NULL;
    struct dirent *dirent;
    char *dir_path = NULL, *prefix = NULL, *ptr;
    time_t ts1, ts2;

    assert((from_ts && to_ts) || (from_ts && !to_ts) || (!from_ts && !to_ts));

    *file_from_ts = 0;
    *file_to_ts = 0;

    if ((err_info = srpjson_get_notif_dir(srpntf_name, &dir_path))) {
        goto cleanup;
    }

    dir = opendir(dir_path);
    if (!dir) {
        if (errno != ENOENT) {
            srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Opening directory \"%s\" failed (%s).",
                    dir_path, strerror(errno));
        }
        goto cleanup;
    }

    /* this is the prefix for all notification files of this module */
    pref_len = asprintf(&prefix, "%s.notif.", mod_name);
    if (pref_len == -1) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
        goto cleanup;
    }

    while ((dirent = readdir(dir))) {
        if (strncmp(dirent->d_name, prefix, pref_len)) {
            continue;
        }

        /* read timestamps */
        errno = 0;
        ts1 = strtoull(dirent->d_name + pref_len, &ptr, 10);
        if (errno || (ptr[0] != '-')) {
            SRPLG_LOG_WRN(srpntf_name, "Invalid notification file \"%s\" encountered.", dirent->d_name);
            continue;
        }
        ts2 = strtoull(ptr + 1, &ptr, 10);
        if (errno || (ptr[0] != '\0')) {
            SRPLG_LOG_WRN(srpntf_name, "Invalid notification file \"%s\" encountered.", dirent->d_name);
            continue;
        }

        if (ts1 > ts2) {
            /* what? */
            SRPLG_LOG_WRN(srpntf_name, "Invalid notification file \"%s\" encountered.", dirent->d_name);
            continue;
        }

        if (from_ts && to_ts) {
            if ((from_ts > ts1) || (to_ts > ts2) || ((from_ts == ts1) && (to_ts == ts2))) {
                /* this file was already processed */
                continue;
            }

            /* we want the next earliest file */
            if ((*file_from_ts && (ts1 >= *file_from_ts)) && (*file_to_ts && ((ts2 >= *file_to_ts)))) {
                continue;
            }
        } else if (from_ts) {
            if (from_ts > ts2) {
                /* there are no notifications of interest in this file */
                continue;
            }

            /* we want the earliest file */
            if ((*file_from_ts && (ts1 >= *file_from_ts)) && (*file_to_ts && ((ts2 >= *file_to_ts)))) {
                continue;
            }
        } else {
            /* we want the latest file */
            if ((*file_from_ts && (ts1 <= *file_from_ts)) && (*file_to_ts && ((ts2 <= *file_to_ts)))) {
                continue;
            }
        }

        /* remember these timestamps */
        *file_from_ts = ts1;
        *file_to_ts = ts2;
    }

cleanup:
    free(dir_path);
    free(prefix);
    if (dir) {
        closedir(dir);
    }
    return err_info;
}

/**
 * @brief Rename notification file after new notifications were stored in it.
 *
 * @param[in] mod_name Module name.
 * @param[in] old_from_ts Current earliest stored notification.
 * @param[in] old_to_ts Current latest stored notification.
 * @param[in] new_to_ts Newly latest stored notification.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
srpntf_rename_file(const char *mod_name, time_t old_from_ts, time_t old_to_ts, time_t new_to_ts)
{
    sr_error_info_t *err_info = NULL;
    char *old_path = NULL, *new_path = NULL;

    assert(old_to_ts <= new_to_ts);

    if (old_to_ts == new_to_ts) {
        /* nothing to do */
        goto cleanup;
    }

    /* old file name */
    if ((err_info = srpjson_get_notif_path(srpntf_name, mod_name, old_from_ts, old_to_ts, &old_path))) {
        goto cleanup;
    }

    /* new file name */
    if ((err_info = srpjson_get_notif_path(srpntf_name, mod_name, old_from_ts, new_to_ts, &new_path))) {
        goto cleanup;
    }

    /* rename */
    if (rename(old_path, new_path) == -1) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Renaming \"%s\" failed (%s).", old_path, strerror(errno));
        goto cleanup;
    }

    SRPLG_LOG_INF(srpntf_name, "Replay file \"%s\" renamed to \"%s\".", strrchr(old_path, '/') + 1,
            strrchr(new_path, '/') + 1);

cleanup:
    free(old_path);
    free(new_path);
    return err_info;
}

static sr_error_info_t *
srpntf_json_enable(const struct lys_module *mod)
{
    sr_error_info_t *err_info = NULL;
    int r;
    char *dir_path = NULL;

    (void)mod;

    /* notif dir */
    if ((err_info = srpjson_get_notif_dir(srpntf_name, &dir_path))) {
        goto cleanup;
    }
    if (((r = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Access on \"%s\" failed (%s).", dir_path, strerror(errno));
        goto cleanup;
    }
    if (r && (err_info = srpjson_mkpath(srpntf_name, dir_path, SRPJSON_DIR_PERM))) {
        goto cleanup;
    }

cleanup:
    free(dir_path);
    return err_info;
}

static sr_error_info_t *
srpntf_json_disable(const struct lys_module *mod)
{
    (void)mod;

    return NULL;
}

static sr_error_info_t *
srpntf_json_store(const struct lys_module *mod, const struct lyd_node *notif, const struct timespec *notif_ts)
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    struct ly_out *out = NULL;
    struct stat st;
    char *notif_json = NULL;
    uint32_t notif_json_len;
    time_t from_ts, to_ts;
    size_t file_size;

    /* create out */
    if (ly_out_new_memory(&notif_json, 0, &out)) {
        err_info = srpjson_log_err_ly(srpntf_name, mod->ctx);
        goto cleanup;
    }

    /* convert notification into JSON */
    if (lyd_print_all(out, notif, LYD_JSON, LYD_PRINT_SHRINK)) {
        err_info = srpjson_log_err_ly(srpntf_name, mod->ctx);
        goto cleanup;
    }

    /* learn its length */
    notif_json_len = ly_out_printed(out);

    /* find the latest notification file for this module */
    if ((err_info = srpntf_find_file(mod->name, 0, 0, &from_ts, &to_ts))) {
        goto cleanup;
    }

    if (from_ts && to_ts) {
        /* open the file */
        if ((err_info = srpntf_open_file(mod->name, from_ts, to_ts, O_WRONLY | O_APPEND, &fd))) {
            goto cleanup;
        }

        /* get file size */
        if (fstat(fd, &st) == -1) {
            srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Fstat failed (%s).", strerror(errno));
            goto cleanup;
        }
        file_size = st.st_size;

        if (file_size + sizeof *notif_ts + sizeof notif_json_len + notif_json_len <= SRPJSON_NOTIF_FILE_MAX_SIZE * 1024) {
            /* add the notification into the file if there is still space */
            if ((err_info = srpntf_writev_notif(fd, notif_json, notif_json_len, notif_ts))) {
                goto cleanup;
            }

            /* update notification file name */
            if ((err_info = srpntf_rename_file(mod->name, from_ts, to_ts, notif_ts->tv_sec))) {
                goto cleanup;
            }

            /* we are done */
            goto cleanup;
        }

        /* we will create a new file, close this one */
        close(fd);
        fd = -1;
    }

    /* creating a new file */
    if ((err_info = srpntf_open_file(mod->name, notif_ts->tv_sec, notif_ts->tv_sec,
            O_WRONLY | O_APPEND | O_CREAT | O_EXCL, &fd))) {
        goto cleanup;
    }

    /* write the notification */
    if ((err_info = srpntf_writev_notif(fd, notif_json, notif_json_len, notif_ts))) {
        goto cleanup;
    }

cleanup:
    ly_out_free(out, NULL, 0);
    if (fd > -1) {
        close(fd);
    }
    free(notif_json);
    return err_info;
}

struct srpntf_rn_state {
    time_t file_from;
    time_t file_to;
    int fd;
};

static sr_error_info_t *
srpntf_json_replay_next(const struct lys_module *mod, const struct timespec *start, const struct timespec *stop,
        struct lyd_node **notif, struct timespec *notif_ts, void *state)
{
    sr_error_info_t *err_info = NULL;
    int not_found = 0;
    struct srpntf_rn_state *st = *(struct srpntf_rn_state **)state;

    *notif = NULL;

    /* get our state */
    if (!st) {
        st = malloc(sizeof *st);
        if (!st) {
            srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
            goto cleanup;
        }
        *(struct srpntf_rn_state **)state = st;

        /* init */
        st->file_from = start->tv_sec;
        st->file_to = 0;
        st->fd = -1;

        /* open first file */
        goto next_file;
    } else {
        /* continue with reading from the opened file */
        goto next_notif;
    }

    /* is this a valid notification file? */
    while (st->file_from && st->file_to && (st->file_from <= stop->tv_sec)) {
        if (st->fd > -1) {
            close(st->fd);
        }

        /* open the file */
        if ((err_info = srpntf_open_file(mod->name, st->file_from, st->file_to, O_RDONLY, &st->fd))) {
            goto cleanup;
        }

        /* skip all earlier notifications */
        while (1) {
            /* read timestamp */
            if ((err_info = srpntf_read_ts(st->fd, notif_ts))) {
                goto cleanup;
            }

            if (!notif_ts->tv_sec || (srpjson_time_cmp(notif_ts, start) > -1)) {
                /* there can be no more notifications in the specific case when the last notif has timestamp
                 * 100.25 and start time is 100.50, for example, because file is opened only based on seconds */
                break;
            }

            /* skip the notification */
            if ((err_info = srpntf_skip_notif(st->fd))) {
                goto cleanup;
            }
        }

        /* replay notifications until stop is reached */
        while (notif_ts->tv_sec && (srpjson_time_cmp(notif_ts, stop) < 0)) {

            /* parse notification, return it */
            err_info = srpntf_read_notif(st->fd, mod->ctx, notif);
            goto cleanup;

next_notif:
            /* read next timestamp */
            if ((err_info = srpntf_read_ts(st->fd, notif_ts))) {
                goto cleanup;
            }
        }

        /* no more notifications should be replayed */
        if (srpjson_time_cmp(notif_ts, stop) > -1) {
            not_found = 1;
            break;
        }

next_file:
        /* find next notification file and read from it */
        if ((err_info = srpntf_find_file(mod->name, st->file_from, st->file_to, &st->file_from, &st->file_to))) {
            goto cleanup;
        }
    }

    /* no more relevant files */
    not_found = 1;

cleanup:
    if (err_info || not_found) {
        /* free state */
        if (st && (st->fd > -1)) {
            close(st->fd);
        }
        free(st);
        *(struct srpntf_rn_state **)state = NULL;
    }
    return err_info;
}

static sr_error_info_t *
srpntf_json_earliest_get(const struct lys_module *mod, struct timespec *ts)
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    time_t file_from, file_to;

    /* create directory in case does not exist */
    if ((err_info = srpntf_json_enable(mod))) {
        goto cleanup;
    }

    if ((err_info = srpntf_find_file(mod->name, 1, 0, &file_from, &file_to))) {
        goto cleanup;
    }
    if (!file_from) {
        /* no notifications stored */
        memset(ts, 0, sizeof *ts);
        goto cleanup;
    }

    /* open the file */
    if ((err_info = srpntf_open_file(mod->name, file_from, file_to, O_RDONLY, &fd))) {
        goto cleanup;
    }

    /* read first notif timestamp */
    if ((err_info = srpntf_read_ts(fd, ts))) {
        goto cleanup;
    }
    if (!ts->tv_sec) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_INTERNAL, "Unexpected notification file EOF.");
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    return err_info;
}

static sr_error_info_t *
srpntf_json_access_set(const struct lys_module *mod, const char *owner, const char *group, mode_t perm)
{
    sr_error_info_t *err_info = NULL;
    time_t file_from, file_to;
    char *path = NULL;

    assert(mod && (owner || group || perm));

    if ((err_info = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return err_info;
    }
    while (file_from && file_to) {
        /* get next notification file path */
        if ((err_info = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
            return err_info;
        }

        /* update notification file permissions and owner */
        err_info = srpjson_chmodown(srpntf_name, path, owner, group, perm);
        free(path);
        if (err_info) {
            return err_info;
        }
    }

    return NULL;
}

static sr_error_info_t *
srpntf_json_access_get(const struct lys_module *mod, char **owner, char **group, mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    int r;
    time_t file_from, file_to;
    struct stat st;
    char *path;

    if (owner) {
        *owner = NULL;
    }
    if (group) {
        *group = NULL;
    }

    /* notif interval */
    if ((err_info = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return err_info;
    }

    if (!file_from && !file_to) {
        srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_NOT_FOUND, "No notifications stored for \"%s\".", mod->name);
        return err_info;
    }

    /* path */
    if ((err_info = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
        return err_info;
    }

    /* stat */
    r = stat(path, &st);
    free(path);
    if (r == -1) {
        if (errno == EACCES) {
            srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_UNAUTHORIZED, "Learning \"%s\" permissions failed.",
                    mod->name);
        } else {
            srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Stat of \"%s\" failed (%s).", path, strerror(errno));
        }
        return err_info;
    }

    /* get owner */
    if (owner && (err_info = srpjson_get_pwd(srpntf_name, &st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (err_info = srpjson_get_grp(srpntf_name, &st.st_gid, group))) {
        goto error;
    }

    /* get perms */
    if (perm) {
        *perm = st.st_mode & 0007777;
    }

    return NULL;

error:
    if (owner) {
        free(*owner);
    }
    if (group) {
        free(*group);
    }
    return err_info;
}

static sr_error_info_t *
srpntf_json_access_check(const struct lys_module *mod, int *read, int *write)
{
    sr_error_info_t *err_info = NULL;
    time_t file_from, file_to;
    char *path;

    /* notif interval */
    if ((err_info = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return err_info;
    }

    if (!file_from && !file_to) {
        /* no notifications, so grant access */
        *read = 1;
        *write = 1;
        return NULL;
    }

    /* path */
    if ((err_info = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
        return err_info;
    }

    /* check read */
    if (read) {
        if (eaccess(path, R_OK) == -1) {
            if (errno == EACCES) {
                *read = 0;
            } else {
                srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Eaccess of \"%s\" failed (%s).", path,
                        strerror(errno));
                goto cleanup;
            }
        } else {
            *read = 1;
        }
    }

    /* check write */
    if (write) {
        if (eaccess(path, W_OK) == -1) {
            if (errno == EACCES) {
                *write = 0;
            } else {
                srplg_log_errinfo(&err_info, srpntf_name, NULL, SR_ERR_SYS, "Eaccess of \"%s\" failed (%s).", path,
                        strerror(errno));
                goto cleanup;
            }
        } else {
            *write = 1;
        }
    }

cleanup:
    free(path);
    return err_info;
}

const struct srplg_ntf_s srpntf_json = {
    .name = srpntf_name,
    .enable_cb = srpntf_json_enable,
    .disable_cb = srpntf_json_disable,
    .store_cb = srpntf_json_store,
    .replay_next_cb = srpntf_json_replay_next,
    .earliest_get_cb = srpntf_json_earliest_get,
    .access_set_cb = srpntf_json_access_set,
    .access_get_cb = srpntf_json_access_get,
    .access_check_cb = srpntf_json_access_check,
};
