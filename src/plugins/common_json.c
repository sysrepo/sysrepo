/**
 * @file common_json.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief common routines for JSON plugins
 *
 * @copyright
 * Copyright (c) 2021 - 2022 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2022 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "common_json.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "compat.h"
#include "config.h"
#include "sysrepo.h"

int
srpjson_writev(const char *plg_name, int fd, struct iovec *iov, int iovcnt)
{
    ssize_t ret;
    size_t written;

    do {
        errno = 0;
        ret = writev(fd, iov, iovcnt);
        if (errno == EINTR) {
            /* it is fine */
            ret = 0;
        } else if (errno) {
            SRPLG_LOG_ERR(plg_name, "Writev failed (%s).", strerror(errno));
            return SR_ERR_SYS;
        }
        assert(ret > -1);
        written = ret;

        /* skip what was written */
        do {
            written -= iov[0].iov_len;
            ++iov;
            --iovcnt;
        } while (iovcnt && (written >= iov[0].iov_len));

        /* a vector was written only partially */
        if (written) {
            assert(iovcnt);
            assert(iov[0].iov_len > written);

            iov[0].iov_base = ((char *)iov[0].iov_base) + written;
            iov[0].iov_len -= written;
        }
    } while (iovcnt);

    return SR_ERR_OK;
}

int
srpjson_read(const char *plg_name, int fd, void *buf, size_t count)
{
    ssize_t ret;
    size_t have_read;

    have_read = 0;
    do {
        errno = 0;
        ret = read(fd, ((char *)buf) + have_read, count - have_read);
        if (!ret) {
            /* EOF */
            return SR_ERR_OK;
        }
        if ((ret == -1) || ((ret < (signed)(count - have_read)) && errno && (errno != EINTR))) {
            SRPLG_LOG_ERR(plg_name, "Read failed (%s).", strerror(errno));
            return SR_ERR_SYS;
        }

        have_read += ret;
    } while (have_read < count);

    return SR_ERR_OK;
}

int
srpjson_file_exists(const char *plg_name, const char *path)
{
    int ret;

    errno = 0;
    ret = access(path, F_OK);
    if ((ret == -1) && (errno != ENOENT)) {
        SRPLG_LOG_WRN(plg_name, "Failed to check existence of the file \"%s\" (%s).", path, strerror(errno));
        return 0;
    }

    if (ret) {
        assert(errno == ENOENT);
        return 0;
    }
    return 1;
}

int
srpjson_shm_prefix(const char *plg_name, const char **prefix)
{
    int rc = SR_ERR_OK;

    *prefix = getenv(SR_SHM_PREFIX_ENV);
    if (*prefix == NULL) {
        *prefix = SR_SHM_PREFIX_DEFAULT;
    } else if (strchr(*prefix, '/')) {
        *prefix = NULL;
        SRPLG_LOG_ERR(plg_name, "%s cannot contain slashes.", SR_SHM_PREFIX_ENV);
        rc = SR_ERR_INVAL_ARG;
    }

    return rc;
}

const char *
srpjson_ds2str(sr_datastore_t ds)
{
    switch (ds) {
    case SR_DS_RUNNING:
        return "running";
    case SR_DS_STARTUP:
        return "startup";
    case SR_DS_CANDIDATE:
        return "candidate";
    case SR_DS_OPERATIONAL:
        return "operational";
    case SR_DS_FACTORY_DEFAULT:
        return "factory-default";
    }

    return NULL;
}

void
srpjson_log_err_ly(const char *plg_name, const struct ly_ctx *ly_ctx)
{
    struct ly_err_item *e;

    e = ly_err_first(ly_ctx);

    /* this function is called only when an error is expected, but it is still possible there
     * will be none -> libyang problem or simply the error was externally processed, sysrepo is
     * unable to detect that */
    if (!e) {
        SRPLG_LOG_ERR(plg_name, "Unknown libyang error.");
        return;
    }

    do {
        if (e->level == LY_LLWRN) {
            SRPLG_LOG_WRN(plg_name, "%s", e->msg);
        } else {
            assert(e->level == LY_LLERR);
            SRPLG_LOG_ERR(plg_name, "%s", e->msg);
        }

        e = e->next;
    } while (e);

    ly_err_clean((struct ly_ctx *)ly_ctx, NULL);
}

int
srpjson_open(const char *path, int flags, mode_t mode)
{
    int fd;

    assert(!(flags & O_CREAT) || mode);

    /* O_NOFOLLOW enforces that files are not symlinks -- all opened
     *   files are created by sysrepo so there cannot be any symlinks.
     * O_CLOEXEC enforces that forking with an open sysrepo connection
     *   is forbidden.
     */
    flags |= O_NOFOLLOW | O_CLOEXEC;

    /* apply umask on mode */
    mode &= ~SR_UMASK;

    /* open the file, process umask may affect the permissions if creating it */
    fd = open(path, flags, mode);
    if (fd == -1) {
        return -1;
    }

    if (flags & O_CREAT) {
        /* set correct permissions */
        if (fchmod(fd, mode) == -1) {
            close(fd);
            return -1;
        }
    }

    return fd;
}

int
srpjson_open_error(const char *plg_name, const char *path)
{
    FILE *f;
    char buf[8], *ret = NULL;

    SRPLG_LOG_ERR(plg_name, "Opening \"%s\" failed (%s).", path, strerror(errno));
    if ((errno == EACCES) && !geteuid()) {
        /* check kernel parameter value of fs.protected_regular */
        f = fopen("/proc/sys/fs/protected_regular", "r");
        if (f) {
            ret = fgets(buf, sizeof(buf), f);
            fclose(f);
        }
    }
    if (ret && (atoi(buf) != 0)) {
        SRPLG_LOG_ERR(plg_name, "Caused by kernel parameter \"fs.protected_regular\", which must be \"0\" "
                "(currently \"%d\").", atoi(buf));
    }

    return SR_ERR_SYS;
}

int
srpjson_get_pwd(const char *plg_name, uid_t *uid, char **user)
{
    int rc = SR_ERR_OK, r;
    struct passwd pwd, *pwd_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(uid && user);

    do {
        if (!buflen) {
            /* learn suitable buffer size */
            buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            /* enlarge buffer */
            buflen += 2048;
        }

        /* allocate some buffer */
        mem = realloc(buf, buflen);
        if (!mem) {
            SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        buf = mem;

        if (*user) {
            /* user -> UID */
            r = getpwnam_r(*user, &pwd, buf, buflen, &pwd_p);
        } else {
            /* UID -> user */
            r = getpwuid_r(*uid, &pwd, buf, buflen, &pwd_p);
        }
    } while (r && (r == ERANGE));
    if (r) {
        if (*user) {
            SRPLG_LOG_ERR(plg_name, "Retrieving user \"%s\" passwd entry failed (%s).", *user, strerror(r));
        } else {
            SRPLG_LOG_ERR(plg_name, "Retrieving UID \"%lu\" passwd entry failed (%s).", (unsigned long int)*uid, strerror(r));
        }
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    } else if (!pwd_p) {
        if (*user) {
            SRPLG_LOG_ERR(plg_name, "Retrieving user \"%s\" passwd entry failed (No such user).", *user);
        } else {
            SRPLG_LOG_ERR(plg_name, "Retrieving UID \"%lu\" passwd entry failed (No such UID).", (unsigned long int)*uid);
        }
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    if (*user) {
        /* assign UID */
        *uid = pwd.pw_uid;
    } else {
        /* assign user */
        *user = strdup(pwd.pw_name);
        if (!*user) {
            SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
    }

    /* success */

cleanup:
    free(buf);
    return rc;
}

int
srpjson_get_grp(const char *plg_name, gid_t *gid, char **group)
{
    int rc = SR_ERR_OK, r;
    struct group grp, *grp_p;
    char *buf = NULL, *mem;
    ssize_t buflen = 0;

    assert(gid && group);

    do {
        if (!buflen) {
            /* learn suitable buffer size */
            buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
            if (buflen == -1) {
                buflen = 2048;
            }
        } else {
            /* enlarge buffer */
            buflen += 2048;
        }

        /* allocate some buffer */
        mem = realloc(buf, buflen);
        if (!mem) {
            SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
        buf = mem;

        if (*group) {
            /* group -> GID */
            r = getgrnam_r(*group, &grp, buf, buflen, &grp_p);
        } else {
            /* GID -> group */
            r = getgrgid_r(*gid, &grp, buf, buflen, &grp_p);
        }
    } while (r && (r == ERANGE));
    if (r) {
        if (*group) {
            SRPLG_LOG_ERR(plg_name, "Retrieving group \"%s\" grp entry failed (%s).", *group, strerror(r));
        } else {
            SRPLG_LOG_ERR(plg_name, "Retrieving GID \"%lu\" grp entry failed (%s).", (unsigned long int)*gid, strerror(r));
        }
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    } else if (!grp_p) {
        if (*group) {
            SRPLG_LOG_ERR(plg_name, "Retrieving group \"%s\" grp entry failed (No such group).", *group);
        } else {
            SRPLG_LOG_ERR(plg_name, "Retrieving GID \"%lu\" grp entry failed (No such GID).", (unsigned long int)*gid);
        }
        rc = SR_ERR_NOT_FOUND;
        goto cleanup;
    }

    if (*group) {
        /* assign GID */
        *gid = grp.gr_gid;
    } else {
        /* assign group */
        *group = strdup(grp.gr_name);
        if (!*group) {
            SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }
    }

    /* success */

cleanup:
    free(buf);
    return rc;
}

int
srpjson_chmodown(const char *plg_name, const char *path, const char *owner, const char *group, mode_t perm)
{
    int rc;
    uid_t uid = -1;
    gid_t gid = -1;

    assert(path);

    if (perm) {
        if (perm > 00777) {
            SRPLG_LOG_ERR(plg_name, "Invalid permissions 0%.3o.", perm);
            return SR_ERR_INVAL_ARG;
        } else if (perm & 00111) {
            SRPLG_LOG_ERR(plg_name, "Setting execute permissions has no effect.");
            return SR_ERR_INVAL_ARG;
        }
    }

    /* we are going to change the owner */
    if (owner && (rc = srpjson_get_pwd(plg_name, &uid, (char **)&owner))) {
        return rc;
    }

    /* we are going to change the group */
    if (group && (rc = srpjson_get_grp(plg_name, &gid, (char **)&group))) {
        return rc;
    }

    /* apply owner changes, if any */
    if (chown(path, uid, gid) == -1) {
        SRPLG_LOG_ERR(plg_name, "Changing owner of \"%s\" failed (%s).", path, strerror(errno));
        if ((errno == EACCES) || (errno == EPERM)) {
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            rc = SR_ERR_INTERNAL;
        }
        return rc;
    }

    /* apply permission changes, if any */
    if (perm && (chmod(path, perm) == -1)) {
        SRPLG_LOG_ERR(plg_name, "Changing permissions (mode) of \"%s\" failed (%s).", path, strerror(errno));
        if ((errno == EACCES) || (errno == EPERM)) {
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            rc = SR_ERR_INTERNAL;
        }
        return rc;
    }

    return SR_ERR_OK;
}

int
srpjson_cp_path(const char *plg_name, const char *to, const char *from)
{
    int rc = SR_ERR_OK, fd_to = -1, fd_from = -1;
    char *out_ptr, buf[4096];
    ssize_t nread, nwritten;

    /* open "from" file */
    fd_from = srpjson_open(from, O_RDONLY, 0);
    if (fd_from < 0) {
        rc = srpjson_open_error(plg_name, from);
        goto cleanup;
    }

    /* open "to" */
    fd_to = srpjson_open(to, O_WRONLY | O_TRUNC, 0);
    if (fd_to < 0) {
        rc = srpjson_open_error(plg_name, to);
        goto cleanup;
    }

    while ((nread = read(fd_from, buf, sizeof buf)) > 0) {
        out_ptr = buf;
        do {
            nwritten = write(fd_to, out_ptr, nread);
            if (nwritten >= 0) {
                nread -= nwritten;
                out_ptr += nwritten;
            } else if (errno != EINTR) {
                SRPLG_LOG_ERR(plg_name, "Writing data failed (%s).", strerror(errno));
                rc = SR_ERR_SYS;
                goto cleanup;
            }
        } while (nread > 0);
    }
    if (nread == -1) {
        SRPLG_LOG_ERR(plg_name, "Reading data failed (%s).", strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

cleanup:
    if (fd_from > -1) {
        close(fd_from);
    }
    if (fd_to > -1) {
        close(fd_to);
    }
    return rc;
}

int
srpjson_mkpath(const char *plg_name, char *path, mode_t mode)
{
    int rc = SR_ERR_OK, r;
    char *p = NULL;
    const char *group = SR_GROUP;
    gid_t gid;

    assert(path[0] == '/');

    /* apply umask on mode */
    mode &= ~SR_UMASK;

    /* get GID of the group */
    if (strlen(SR_GROUP) && (rc = srpjson_get_grp(plg_name, &gid, (char **)&group))) {
        goto cleanup;
    }

    /* create each directory in the path */
    for (p = strchr(path + 1, '/'); p; p = strchr(p + 1, '/')) {
        *p = '\0';
        if (((r = mkdir(path, mode)) == -1) && (errno != EEXIST)) {
            SRPLG_LOG_ERR(plg_name, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }

        /* update perms and group */
        if (!r) {
            if (chmod(path, mode) == -1) {
                SRPLG_LOG_ERR(plg_name, "Changing permissions of directory \"%s\" failed (%s).", path, strerror(errno));
                rc = SR_ERR_SYS;
                goto cleanup;
            }
            if (strlen(SR_GROUP) && (chown(path, -1, gid) == -1)) {
                SRPLG_LOG_ERR(plg_name, "Changing group of directory \"%s\" failed (%s).", path, strerror(errno));
                rc = SR_ERR_SYS;
                goto cleanup;
            }
        }

        *p = '/';
    }

    /* create the last directory in the path */
    if (((r = mkdir(path, mode)) == -1) && (errno != EEXIST)) {
        SRPLG_LOG_ERR(plg_name, "Creating directory \"%s\" failed (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    /* update perms and group */
    if (!r) {
        if (chmod(path, mode) == -1) {
            SRPLG_LOG_ERR(plg_name, "Changing permissions of directory \"%s\" failed (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
        if (strlen(SR_GROUP) && (chown(path, -1, gid) == -1)) {
            SRPLG_LOG_ERR(plg_name, "Changing group of directory \"%s\" failed (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
    }

cleanup:
    if (p) {
        *p = '/';
    }
    return rc;
}

int
srpjson_time_cmp(const struct timespec *ts1, const struct timespec *ts2)
{
    /* seconds diff */
    if (ts1->tv_sec > ts2->tv_sec) {
        return 1;
    } else if (ts1->tv_sec < ts2->tv_sec) {
        return -1;
    }

    /* nanoseconds diff */
    if (ts1->tv_nsec > ts2->tv_nsec) {
        return 1;
    } else if (ts1->tv_nsec < ts2->tv_nsec) {
        return -1;
    }

    return 0;
}

int
srpjson_get_startup_dir(const char *plg_name, char **path)
{
    if (SR_STARTUP_PATH[0]) {
        *path = strdup(SR_STARTUP_PATH);
    } else {
        if (asprintf(path, "%s/data", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }

    if (!*path) {
        SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
        return SR_ERR_NO_MEMORY;
    }
    return SR_ERR_OK;
}

int
srpjson_get_path(const char *plg_name, const char *mod_name, sr_datastore_t ds, char **path)
{
    int r = 0, rc;
    const char *prefix;

    *path = NULL;

    switch (ds) {
    case SR_DS_STARTUP:
        if (SR_STARTUP_PATH[0]) {
            r = asprintf(path, "%s/%s.startup", SR_STARTUP_PATH, mod_name);
        } else {
            r = asprintf(path, "%s/data/%s.startup", sr_get_repo_path(), mod_name);
        }
        break;
    case SR_DS_FACTORY_DEFAULT:
        if (SR_FACTORY_DEFAULT_PATH[0]) {
            r = asprintf(path, "%s/%s.factory-default", SR_FACTORY_DEFAULT_PATH, mod_name);
        } else {
            r = asprintf(path, "%s/data/%s.factory-default", sr_get_repo_path(), mod_name);
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((rc = srpjson_shm_prefix(plg_name, &prefix))) {
            return rc;
        }

        r = asprintf(path, "%s/%s_%s.%s", SR_SHM_DIR, prefix, mod_name, srpjson_ds2str(ds));
        break;
    }

    if (r == -1) {
        *path = NULL;
        SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
        return SR_ERR_NO_MEMORY;
    }

    return SR_ERR_OK;
}

int
srpjson_get_perm_path(const char *plg_name, const char *mod_name, sr_datastore_t ds, char **path)
{
    int r = 0;

    *path = NULL;

    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        return SR_ERR_INTERNAL;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if (SR_STARTUP_PATH[0]) {
            r = asprintf(path, "%s/%s.%s.perm", SR_STARTUP_PATH, mod_name, srpjson_ds2str(ds));
        } else {
            r = asprintf(path, "%s/data/%s.%s.perm", sr_get_repo_path(), mod_name, srpjson_ds2str(ds));
        }
        break;
    }

    if (r == -1) {
        *path = NULL;
        SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
        return SR_ERR_NO_MEMORY;
    }

    return SR_ERR_OK;
}

int
srpjson_get_notif_dir(const char *plg_name, char **path)
{
    if (SR_NOTIFICATION_PATH[0]) {
        *path = strdup(SR_NOTIFICATION_PATH);
    } else {
        if (asprintf(path, "%s/data/notif", sr_get_repo_path()) == -1) {
            *path = NULL;
        }
    }

    if (!*path) {
        SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
        return SR_ERR_NO_MEMORY;
    }
    return SR_ERR_OK;
}

int
srpjson_get_notif_path(const char *plg_name, const char *mod_name, time_t from_ts, time_t to_ts, char **path)
{
    int r;

    if (SR_NOTIFICATION_PATH[0]) {
        r = asprintf(path, "%s/%s.notif.%lu-%lu", SR_NOTIFICATION_PATH, mod_name, from_ts, to_ts);
    } else {
        r = asprintf(path, "%s/data/notif/%s.notif.%lu-%lu", sr_get_repo_path(), mod_name, from_ts, to_ts);
    }

    if (r == -1) {
        SRPLG_LOG_ERR(plg_name, "Memory allocation failed.");
        return SR_ERR_NO_MEMORY;
    }
    return SR_ERR_OK;
}

int
srpjson_module_has_data(const struct lys_module *ly_mod, int state_data)
{
    const struct lysc_node *root;

    LY_LIST_FOR(ly_mod->compiled->data, root) {
        if (!(root->nodetype & (LYS_CONTAINER | LYS_LIST | LYS_LEAF | LYS_LEAFLIST | LYS_ANYDATA | LYS_CHOICE))) {
            continue;
        }

        if ((root->flags & LYS_CONFIG_W) || (state_data && (root->flags & LYS_CONFIG_R))) {
            return 1;
        }
    }

    return 0;
}
