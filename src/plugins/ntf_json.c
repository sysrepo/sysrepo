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

#include "compat.h"
#include "common_json.h"
#include "sysrepo.h"

#define srpntf_name "JSON notif" /**< plugin name */

/**
 * @brief Write notification into fd using vector IO.
 *
 * @param[in] notif_json Notification in JSON format.
 * @param[in] notif_json_len Length of notification in JSON format.
 * @param[in] notif_ts Notification timestamp.
 * @return SR err value.
 */
static int
srpntf_writev_notif(int fd, const char *notif_json, uint32_t notif_json_len, const struct timespec *notif_ts)
{
    int rc;
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
    if ((rc = srpjson_writev(srpntf_name, fd, iov, 3))) {
        return rc;
    }

    /* fsync */
    if (fsync(fd) == -1) {
        SRPLG_LOG_ERR(srpntf_name, "Fsync failed (%s).", strerror(errno));
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
}

/**
 * @brief Read timestamp from a notification file.
 *
 * @param[in] notif_fd Notification file descriptor.
 * @param[out] notif_ts Notification timestamp, zeroed if EOF reached.
 * @return SR err value.
 */
static int
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
 * @return SR err value.
 */
static int
srpntf_read_notif(int notif_fd, struct ly_ctx *ly_ctx, struct lyd_node **notif)
{
    int rc = SR_ERR_OK;
    char *notif_json = NULL;
    struct ly_in *in = NULL;
    uint32_t notif_json_len;

    /* read the length */
    if ((rc = srpjson_read(srpntf_name, notif_fd, &notif_json_len, sizeof notif_json_len))) {
        goto cleanup;
    }

    /* read the notification */
    notif_json = malloc(notif_json_len + 1);
    if (!notif_json) {
        SRPLG_LOG_ERR(srpntf_name, "Memory allocation failed.");
        rc = SR_ERR_NO_MEMORY;
        goto cleanup;
    }

    if ((rc = srpjson_read(srpntf_name, notif_fd, notif_json, notif_json_len))) {
        goto cleanup;
    }
    notif_json[notif_json_len] = '\0';

    /* parse the notification */
    ly_in_new_memory(notif_json, &in);
    if (lyd_parse_op(ly_ctx, NULL, in, LYD_JSON, LYD_TYPE_NOTIF_YANG, notif, NULL)) {
        srpjson_log_err_ly(srpntf_name, ly_ctx);
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    free(notif_json);
    ly_in_free(in, 0);
    return rc;
}

/**
 * @brief Skip a notification in a notification file.
 *
 * @param[in] notif_fd Notification file descriptor.
 * @return SR err value.
 */
static int
srpntf_skip_notif(int notif_fd)
{
    int rc;
    uint32_t notif_json_len;

    /* read notification length */
    if ((rc = srpjson_read(srpntf_name, notif_fd, &notif_json_len, sizeof notif_json_len))) {
        return rc;
    }

    /* skip the notification */
    if (lseek(notif_fd, notif_json_len, SEEK_CUR) == -1) {
        SRPLG_LOG_ERR(srpntf_name, "Lseek failed (%s).", strerror(errno));
        return SR_ERR_SYS;
    }

    return SR_ERR_OK;
}

/**
 * @brief Open notification replay file.
 *
 * @param[in] mod_name Module name.
 * @param[in] from_ts Earliest stored notification.
 * @param[in] to_ts Latest stored notification.
 * @param[in] flags Open flags to use.
 * @param[out] notif_fd Opened file descriptor.
 * @return SR err value.
 */
static int
srpntf_open_file(const char *mod_name, time_t from_ts, time_t to_ts, int flags, int *notif_fd)
{
    int rc = SR_ERR_OK;
    char *path = NULL;
    mode_t perm = SRPJSON_NOTIF_PERM;

    *notif_fd = -1;

    if ((rc = srpjson_get_notif_path(srpntf_name, mod_name, from_ts, to_ts, &path))) {
        goto cleanup;
    }

    *notif_fd = srpjson_open(path, flags, perm);
    if (*notif_fd == -1) {
        rc = srpjson_open_error(srpntf_name, path);
        goto cleanup;
    }

    if ((flags & O_CREAT) && (flags & O_EXCL)) {
        SRPLG_LOG_INF(srpntf_name, "Replay file \"%s\" created.", strrchr(path, '/') + 1);
    }

cleanup:
    free(path);
    return rc;
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
 * @return SR err value.
 */
static int
srpntf_find_file(const char *mod_name, time_t from_ts, time_t to_ts, time_t *file_from_ts, time_t *file_to_ts)
{
    int rc = SR_ERR_OK, pref_len;
    DIR *dir = NULL;
    struct dirent *dirent;
    char *dir_path = NULL, *prefix = NULL, *ptr;
    time_t ts1, ts2;

    assert((from_ts && to_ts) || (from_ts && !to_ts) || (!from_ts && !to_ts));

    *file_from_ts = 0;
    *file_to_ts = 0;

    if ((rc = srpjson_get_notif_dir(srpntf_name, &dir_path))) {
        goto cleanup;
    }

    dir = opendir(dir_path);
    if (!dir) {
        if (errno != ENOENT) {
            SRPLG_LOG_ERR(srpntf_name, "Opening directory \"%s\" failed (%s).", dir_path, strerror(errno));
            rc = SR_ERR_SYS;
        }
        goto cleanup;
    }

    /* this is the prefix for all notification files of this module */
    pref_len = asprintf(&prefix, "%s.notif.", mod_name);
    if (pref_len == -1) {
        SRPLG_LOG_ERR(srpntf_name, "Memory allocation failed.");
        rc = SR_ERR_NO_MEMORY;
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
    return rc;
}

/**
 * @brief Rename notification file after new notifications were stored in it.
 *
 * @param[in] mod_name Module name.
 * @param[in] old_from_ts Current earliest stored notification.
 * @param[in] old_to_ts Current latest stored notification.
 * @param[in] new_to_ts Newly latest stored notification.
 * @return SR err value.
 */
static int
srpntf_rename_file(const char *mod_name, time_t old_from_ts, time_t old_to_ts, time_t new_to_ts)
{
    int rc = SR_ERR_OK;
    char *old_path = NULL, *new_path = NULL;

    assert(old_to_ts <= new_to_ts);

    if (old_to_ts == new_to_ts) {
        /* nothing to do */
        goto cleanup;
    }

    /* old file name */
    if ((rc = srpjson_get_notif_path(srpntf_name, mod_name, old_from_ts, old_to_ts, &old_path))) {
        goto cleanup;
    }

    /* new file name */
    if ((rc = srpjson_get_notif_path(srpntf_name, mod_name, old_from_ts, new_to_ts, &new_path))) {
        goto cleanup;
    }

    /* rename */
    if (rename(old_path, new_path) == -1) {
        SRPLG_LOG_ERR(srpntf_name, "Renaming \"%s\" failed (%s).", old_path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    SRPLG_LOG_INF(srpntf_name, "Replay file \"%s\" renamed to \"%s\".", strrchr(old_path, '/') + 1,
            strrchr(new_path, '/') + 1);

cleanup:
    free(old_path);
    free(new_path);
    return rc;
}

static int
srpntf_json_enable(const struct lys_module *mod)
{
    int rc = SR_ERR_OK, r;
    char *dir_path = NULL;

    (void)mod;

    /* notif dir */
    if ((rc = srpjson_get_notif_dir(srpntf_name, &dir_path))) {
        goto cleanup;
    }
    if (((r = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        SRPLG_LOG_ERR(srpntf_name, "Access on \"%s\" failed (%s).", dir_path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }
    if (r && (rc = srpjson_mkpath(srpntf_name, dir_path, SRPJSON_DIR_PERM))) {
        goto cleanup;
    }

cleanup:
    free(dir_path);
    return rc;
}

static int
srpntf_json_disable(const struct lys_module *mod)
{
    (void)mod;

    return SR_ERR_OK;
}

static int
srpntf_json_store(const struct lys_module *mod, const struct lyd_node *notif, const struct timespec *notif_ts)
{
    int rc = SR_ERR_OK, fd = -1;
    struct ly_out *out = NULL;
    struct stat st;
    char *notif_json = NULL;
    uint32_t notif_json_len;
    time_t from_ts, to_ts;
    size_t file_size;

    /* create out */
    if (ly_out_new_memory(&notif_json, 0, &out)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* convert notification into JSON */
    if (lyd_print_all(out, notif, LYD_JSON, LYD_PRINT_SHRINK)) {
        srpjson_log_err_ly(srpntf_name, mod->ctx);
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* learn its length */
    notif_json_len = ly_out_printed(out);

    /* find the latest notification file for this module */
    if ((rc = srpntf_find_file(mod->name, 0, 0, &from_ts, &to_ts))) {
        goto cleanup;
    }

    if (from_ts && to_ts) {
        /* open the file */
        if ((rc = srpntf_open_file(mod->name, from_ts, to_ts, O_WRONLY | O_APPEND, &fd))) {
            goto cleanup;
        }

        /* get file size */
        if (fstat(fd, &st) == -1) {
            SRPLG_LOG_ERR(srpntf_name, "Fstat failed (%s).", strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
        file_size = st.st_size;

        if (file_size + sizeof *notif_ts + sizeof notif_json_len + notif_json_len <= SRPJSON_NOTIF_FILE_MAX_SIZE * 1024) {
            /* add the notification into the file if there is still space */
            if ((rc = srpntf_writev_notif(fd, notif_json, notif_json_len, notif_ts))) {
                goto cleanup;
            }

            /* update notification file name */
            if ((rc = srpntf_rename_file(mod->name, from_ts, to_ts, notif_ts->tv_sec))) {
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
    if ((rc = srpntf_open_file(mod->name, notif_ts->tv_sec, notif_ts->tv_sec, O_WRONLY | O_APPEND | O_CREAT | O_EXCL, &fd))) {
        goto cleanup;
    }

    /* write the notification */
    if ((rc = srpntf_writev_notif(fd, notif_json, notif_json_len, notif_ts))) {
        goto cleanup;
    }

cleanup:
    ly_out_free(out, NULL, 0);
    if (fd > -1) {
        close(fd);
    }
    free(notif_json);
    return rc;
}

struct srpntf_rn_state {
    time_t file_from;
    time_t file_to;
    int fd;
};

static int
srpntf_json_replay_next(const struct lys_module *mod, const struct timespec *start, const struct timespec *stop,
        struct lyd_node **notif, struct timespec *notif_ts, void *state)
{
    int rc = SR_ERR_OK;
    struct srpntf_rn_state *st = *(struct srpntf_rn_state **)state;

    *notif = NULL;

    /* get our state */
    if (!st) {
        st = malloc(sizeof *st);
        if (!st) {
            SRPLG_LOG_ERR(srpntf_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
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
        if ((rc = srpntf_open_file(mod->name, st->file_from, st->file_to, O_RDONLY, &st->fd))) {
            goto cleanup;
        }

        /* skip all earlier notifications */
        while (1) {
            /* read timestamp */
            if ((rc = srpntf_read_ts(st->fd, notif_ts))) {
                goto cleanup;
            }

            if (!notif_ts->tv_sec || (srpjson_time_cmp(notif_ts, start) > -1)) {
                /* there can be no more notifications in the specific case when the last notif has timestamp
                 * 100.25 and start time is 100.50, for example, because file is opened only based on seconds */
                break;
            }

            /* skip the notification */
            if ((rc = srpntf_skip_notif(st->fd))) {
                goto cleanup;
            }
        }

        /* replay notifications until stop is reached */
        while (notif_ts->tv_sec && (srpjson_time_cmp(notif_ts, stop) < 0)) {

            /* parse notification, return it */
            rc = srpntf_read_notif(st->fd, mod->ctx, notif);
            goto cleanup;

next_notif:
            /* read next timestamp */
            if ((rc = srpntf_read_ts(st->fd, notif_ts))) {
                goto cleanup;
            }
        }

        /* no more notifications should be replayed */
        if (srpjson_time_cmp(notif_ts, stop) > -1) {
            rc = SR_ERR_NOT_FOUND;
            break;
        }

next_file:
        /* find next notification file and read from it */
        if ((rc = srpntf_find_file(mod->name, st->file_from, st->file_to, &st->file_from, &st->file_to))) {
            goto cleanup;
        }
    }

    /* no more relevant files */
    rc = SR_ERR_NOT_FOUND;

cleanup:
    if (rc && st) {
        /* free state */
        if (st->fd > -1) {
            close(st->fd);
        }
        free(st);
    }
    return rc;
}

static int
srpntf_json_earliest_get(const struct lys_module *mod, struct timespec *ts)
{
    int rc = SR_ERR_OK, fd = -1;
    time_t file_from, file_to;

    /* create directory in case does not exist */
    if ((rc = srpntf_json_enable(mod))) {
        goto cleanup;
    }

    if ((rc = srpntf_find_file(mod->name, 1, 0, &file_from, &file_to))) {
        goto cleanup;
    }
    if (!file_from) {
        /* no notifications stored */
        memset(ts, 0, sizeof *ts);
        goto cleanup;
    }

    /* open the file */
    if ((rc = srpntf_open_file(mod->name, file_from, file_to, O_RDONLY, &fd))) {
        goto cleanup;
    }

    /* read first notif timestamp */
    if ((rc = srpntf_read_ts(fd, ts))) {
        goto cleanup;
    }
    if (!ts->tv_sec) {
        SRPLG_LOG_ERR(srpntf_name, "Unexpected notification file EOF.");
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    return rc;
}

static int
srpntf_json_access_set(const struct lys_module *mod, const char *owner, const char *group, mode_t perm)
{
    int rc;
    time_t file_from, file_to;
    char *path = NULL;

    assert(mod && (owner || group || perm));

    if ((rc = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return rc;
    }
    while (file_from && file_to) {
        /* get next notification file path */
        if ((rc = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
            return rc;
        }

        /* update notification file permissions and owner */
        rc = srpjson_chmodown(srpntf_name, path, owner, group, perm);
        free(path);
        if (rc) {
            return rc;
        }
    }

    return SR_ERR_OK;
}

static int
srpntf_json_access_get(const struct lys_module *mod, char **owner, char **group, mode_t *perm)
{
    int rc = SR_ERR_OK, r;
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
    if ((rc = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return rc;
    }

    if (!file_from && !file_to) {
        SRPLG_LOG_ERR(srpntf_name, "No notifications stored for \"%s\".", mod->name);
        return SR_ERR_NOT_FOUND;
    }

    /* path */
    if ((rc = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
        return rc;
    }

    /* stat */
    r = stat(path, &st);
    free(path);
    if (r == -1) {
        if (errno == EACCES) {
            SRPLG_LOG_ERR(srpntf_name, "Learning \"%s\" permissions failed.", mod->name);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SRPLG_LOG_ERR(srpntf_name, "Stat of \"%s\" failed (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
        }
        return rc;
    }

    /* get owner */
    if (owner && (rc = srpjson_get_pwd(srpntf_name, &st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (rc = srpjson_get_grp(srpntf_name, &st.st_gid, group))) {
        goto error;
    }

    /* get perms */
    if (perm) {
        *perm = st.st_mode & 0007777;
    }

    return rc;

error:
    if (owner) {
        free(*owner);
    }
    if (group) {
        free(*group);
    }
    return rc;
}

static int
srpntf_json_access_check(const struct lys_module *mod, int *read, int *write)
{
    int rc = SR_ERR_OK;
    time_t file_from, file_to;
    char *path;

    /* notif interval */
    if ((rc = srpntf_find_file(mod->name, 1, 1, &file_from, &file_to))) {
        return rc;
    }

    if (!file_from && !file_to) {
        /* no notifications, so grant access */
        *read = 1;
        *write = 1;
        return SR_ERR_OK;
    }

    /* path */
    if ((rc = srpjson_get_notif_path(srpntf_name, mod->name, file_from, file_to, &path))) {
        return rc;
    }

    /* check read */
    if (read) {
        if (eaccess(path, R_OK) == -1) {
            if (errno == EACCES) {
                *read = 0;
            } else {
                SRPLG_LOG_ERR(srpntf_name, "Eaccess of \"%s\" failed (%s).", path, strerror(errno));
                rc = SR_ERR_SYS;
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
                SRPLG_LOG_ERR(srpntf_name, "Eaccess of \"%s\" failed (%s).", path, strerror(errno));
                rc = SR_ERR_SYS;
                goto cleanup;
            }
        } else {
            *write = 1;
        }
    }

cleanup:
    free(path);
    return rc;
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
