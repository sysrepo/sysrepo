/**
 * @file ds_json.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief internal JSON datastore plugin
 *
 * @copyright
 * Copyright (c) 2021 - 2023 Deutsche Telekom AG.
 * Copyright (c) 2021 - 2023 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE
#define _POSIX_C_SOURCE 200809L /* stat.mtim */

#include "compat.h"
#include "plugins_datastore.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
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

#define srpds_name "JSON DS file"  /**< plugin name */

static int srpds_json_load(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths, uint32_t xpath_count,
        struct lyd_node **mod_data);

static int srpds_json_access_get(const struct lys_module *mod, sr_datastore_t ds, char **owner, char **group,
        mode_t *perm);

static int
srpds_json_store_(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_data, const char *owner,
        const char *group, mode_t perm, int make_backup)
{
    int rc = SR_ERR_OK;
    struct stat st;
    char *path = NULL, *bck_path = NULL;
    int fd = -1, backup = 0, creat = 0;
    uint32_t print_opts;
    off_t size;

    /* get path */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    if (make_backup && (ds == SR_DS_STARTUP)) {
        /* get original file perms */
        if (stat(path, &st) == -1) {
            if (errno == EACCES) {
                SRPLG_LOG_ERR(srpds_name, "Learning \"%s\" permissions failed.", mod->name);
                rc = SR_ERR_UNAUTHORIZED;
            } else {
                SRPLG_LOG_ERR(srpds_name, "Stat of \"%s\" failed (%s).", path, strerror(errno));
                rc = SR_ERR_SYS;
            }
            goto cleanup;
        }

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SRPJSON_FILE_BACKUP_SUFFIX) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }

        /* create backup file with same permissions (not owner/group because it may be different and this process
         * not has permissions to use that owner/group) */
        if ((fd = srpjson_open(bck_path, O_WRONLY | O_CREAT | O_EXCL, st.st_mode)) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Opening \"%s\" failed (%s).", bck_path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
        backup = 1;

        /* close */
        close(fd);
        fd = -1;

        /* back up any existing file */
        if ((rc = srpjson_cp_path(srpds_name, bck_path, path))) {
            goto cleanup;
        }
    }

    if (perm) {
        /* try to create the file */
        fd = srpjson_open(path, O_WRONLY | O_CREAT | O_EXCL, perm);
        if (fd > 0) {
            creat = 1;
        }
    }
    if (fd == -1) {
        /* open existing file */
        fd = srpjson_open(path, O_WRONLY, perm);
    }
    if (fd == -1) {
        rc = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    if (creat && (owner || group)) {
        /* change the owner of the created file */
        if ((rc = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
            goto cleanup;
        }
    }

    /* print data */
    print_opts = LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS | LYD_PRINT_KEEPEMPTYCONT | LYD_PRINT_WD_IMPL_TAG;
    if (lyd_print_fd(fd, mod_data, LYD_JSON, print_opts)) {
        srpjson_log_err_ly(srpds_name, LYD_CTX(mod_data));
        SRPLG_LOG_ERR(srpds_name, "Failed to store data into \"%s\".", path);
        rc = SR_ERR_INTERNAL;
        goto cleanup;
    }

    /* truncate the file to the exact size (to get rid of possible following old data) */
    if ((size = lseek(fd, 0, SEEK_CUR)) == -1) {
        SRPLG_LOG_ERR(srpds_name, "Failed to get the size of \"%s\" (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }
    if (ftruncate(fd, size) == -1) {
        SRPLG_LOG_ERR(srpds_name, "Failed to truncate \"%s\" (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

cleanup:
    /* delete the backup file */
    if (backup && (unlink(bck_path) == -1)) {
        SRPLG_LOG_ERR(srpds_name, "Failed to remove backup \"%s\" (%s).", bck_path, strerror(errno));
        if (!rc) {
            rc = SR_ERR_SYS;
        }
    }

    if (fd > -1) {
        close(fd);
    }
    free(path);
    free(bck_path);
    return rc;
}

/**
 * @brief Initialize persistent datastore file.
 *
 * @param[in] mod Module to initialize.
 * @param[in] ds Datastore.
 * @param[in] owner Owner of the data, may be NULL.
 * @param[in] group Group of the data, may be NULL.
 * @param[in] perm Permissions of the data.
 * @return SR_ERR value.
 */
static int
srpds_json_install_persistent(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    /* check whether the file does not exist */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if (srpjson_file_exists(srpds_name, path)) {
        SRPLG_LOG_ERR(srpds_name, "File \"%s\" already exists.", path);
        rc = SR_ERR_EXISTS;
        goto cleanup;
    }

    /* print empty file to store permissions */
    if ((rc = srpds_json_store_(mod, ds, NULL, owner, group, perm, 0))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_json_install(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK, fd = -1;
    char *path = NULL;

    assert(perm);

    /* startup data dir */
    if ((rc = srpjson_get_startup_dir(srpds_name, &path))) {
        return rc;
    }
    if (!srpjson_file_exists(srpds_name, path) && (rc = srpjson_mkpath(srpds_name, path, SRPJSON_DIR_PERM))) {
        goto cleanup;
    }

    if ((ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        /* persistent DS file install */
        rc = srpds_json_install_persistent(mod, ds, owner, group, perm);
        goto cleanup;
    }

    /* get path to the perm file */
    free(path);
    if ((rc = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* create the file with the correct permissions */
    if ((fd = srpjson_open(path, O_RDONLY | O_CREAT | O_EXCL, perm)) == -1) {
        rc = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    /* update the owner/group of the file */
    if (owner || group) {
        if ((rc = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
            goto cleanup;
        }
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return rc;
}

static int
srpds_json_uninstall(const struct lys_module *mod, sr_datastore_t ds)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    /* unlink data file */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if ((unlink(path) == -1) && ((errno != ENOENT) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT))) {
        /* only startup and factory-default are persistent and must always exist */
        SRPLG_LOG_WRN(srpds_name, "Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }

    if ((ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        /* done */
        goto cleanup;
    }

    /* unlink perm file */
    free(path);
    if ((rc = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if (unlink(path) == -1) {
        SRPLG_LOG_WRN(srpds_name, "Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_json_init(const struct lys_module *mod, sr_datastore_t ds)
{
    int rc = SR_ERR_OK, fd = -1;
    char *owner = NULL, *group = NULL, *path = NULL;
    mode_t perm;

    if (ds != SR_DS_RUNNING) {
        /* startup and factory-default are persistent and candidate with operational exists only if modified */
        return SR_ERR_OK;
    }

    if (!srpjson_module_has_data(mod, 0)) {
        /* no data, do not create the file */
        return SR_ERR_OK;
    }

    /* get owner/group/perms of the datastore file */
    if ((rc = srpds_json_access_get(mod, ds, &owner, &group, &perm))) {
        goto cleanup;
    }

    /* get path to the file */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* create the file with the correct permissions */
    if ((fd = srpjson_open(path, O_WRONLY | O_CREAT | O_EXCL, perm)) == -1) {
        rc = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    /* print empty JSON file */
    if (lyd_print_fd(fd, NULL, LYD_JSON, LYD_PRINT_SHRINK)) {
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* update the owner/group of the file */
    if ((rc = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(owner);
    free(group);
    free(path);
    return rc;
}

static int
srpds_json_store(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *UNUSED(mod_diff),
        const struct lyd_node *mod_data)
{
    mode_t perm = 0;
    int rc;
    char *path = NULL;

    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        /* must exist */
        break;
    case SR_DS_RUNNING:
        /* must exist except for case when all the data were disabled by a feature, which has just been enabled */
    /* fallthrough */
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* get data file path */
        if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        if (srpjson_file_exists(srpds_name, path)) {
            /* file exists */
            break;
        }

        /* get the correct permissions to set for the new file (not owner/group because we may not have permissions to set them) */
        if ((rc = srpds_json_access_get(mod, ds, NULL, NULL, &perm))) {
            goto cleanup;
        }
        break;
    }

    /* store */
    if ((rc = srpds_json_store_(mod, ds, mod_data, NULL, NULL, perm, 1))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return rc;
}

static void
srpds_json_recover(const struct lys_module *mod, sr_datastore_t ds)
{
    char *path = NULL, *bck_path = NULL;
    struct lyd_node *mod_data = NULL;

    /* get path */
    if (srpjson_get_path(srpds_name, mod->name, ds, &path)) {
        goto cleanup;
    }

    /* check whether the file is valid */
    if (!srpds_json_load(mod, ds, NULL, 0, &mod_data)) {
        /* data are valid, nothing to do */
        goto cleanup;
    }

    if (ds == SR_DS_STARTUP) {
        /* there must be a backup file for startup data */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" startup data from a backup.", mod->name);

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SRPJSON_FILE_BACKUP_SUFFIX) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
            goto cleanup;
        }

        /* restore the backup data, avoid changing permissions of the target file */
        if (srpjson_cp_path(srpds_name, path, bck_path)) {
            goto cleanup;
        }

        /* remove the backup file */
        if (unlink(bck_path) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Unlinking \"%s\" failed (%s).", bck_path, strerror(errno));
            goto cleanup;
        }
    } else if (ds == SR_DS_RUNNING) {
        /* perform startup->running data file copy */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" running data from the startup data.", mod->name);

        /* generate the startup data file path */
        if (srpjson_get_path(srpds_name, mod->name, SR_DS_STARTUP, &bck_path)) {
            goto cleanup;
        }

        /* copy startup data to running */
        if (srpjson_cp_path(srpds_name, path, bck_path)) {
            goto cleanup;
        }
    } else {
        /* there is not much to do but remove the corrupted file */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" %s data by removing the corrupted data file.", mod->name,
                srpjson_ds2str(ds));

        if (unlink(path) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Unlinking \"%s\" failed (%s).", path, strerror(errno));
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(bck_path);
    lyd_free_all(mod_data);
}

static int
srpds_json_load(const struct lys_module *mod, sr_datastore_t ds, const char **UNUSED(xpaths), uint32_t UNUSED(xpath_count),
        struct lyd_node **mod_data)
{
    int rc = SR_ERR_OK, fd = -1;
    char *path = NULL;
    uint32_t parse_opts;

    *mod_data = NULL;

    /* prepare correct file path */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* open fd */
    fd = srpjson_open(path, O_RDONLY, 0);
    if (fd == -1) {
        if (errno == ENOENT) {
            switch (ds) {
            case SR_DS_STARTUP:
            case SR_DS_CANDIDATE:
            case SR_DS_FACTORY_DEFAULT:
                /* error */
                break;
            case SR_DS_RUNNING:
                if (!srpjson_module_has_data(mod, 0)) {
                    /* no data */
                    goto cleanup;
                }
                break;
            case SR_DS_OPERATIONAL:
                /* operational empty */
                goto cleanup;
            }
        }

        rc = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    /* set parse options */
    parse_opts = LYD_PARSE_ONLY | LYD_PARSE_ORDERED;
    if (ds == SR_DS_OPERATIONAL) {
        /* edit may include opaque nodes */
        parse_opts |= LYD_PARSE_OPAQ;
    } else {
        parse_opts |= LYD_PARSE_STRICT;
    }
    if ((ds == SR_DS_RUNNING) || (ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        /* always valid datastores */
        parse_opts |= LYD_PARSE_WHEN_TRUE | LYD_PARSE_NO_NEW;
    }

    /* load the data */
    if (lyd_parse_data_fd(mod->ctx, fd, LYD_JSON, parse_opts, 0, mod_data)) {
        srpjson_log_err_ly(srpds_name, mod->ctx);
        rc = SR_ERR_LY;
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return rc;
}

static int
srpds_json_copy(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds)
{
    int rc = SR_ERR_OK, fd = -1;
    char *src_path = NULL, *trg_path = NULL, *owner = NULL, *group = NULL;
    mode_t perm = 0;

    /* target path */
    if ((rc = srpjson_get_path(srpds_name, mod->name, trg_ds, &trg_path))) {
        goto cleanup;
    }

    switch (trg_ds) {
    case SR_DS_STARTUP:
    case SR_DS_RUNNING:
    case SR_DS_FACTORY_DEFAULT:
        /* must exist */
        break;
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if (srpjson_file_exists(srpds_name, trg_path)) {
            /* file exists */
            break;
        }

        /* get the correct permissions to set for the new file */
        if ((rc = srpds_json_access_get(mod, trg_ds, &owner, &group, &perm))) {
            goto cleanup;
        }

        /* create the target file with the correct permissions */
        if ((fd = srpjson_open(trg_path, O_WRONLY | O_CREAT | O_EXCL, perm)) == -1) {
            rc = srpjson_open_error(srpds_name, trg_path);
            goto cleanup;
        }

        /* change the owner/group of the new file */
        if ((rc = srpjson_chmodown(srpds_name, trg_path, owner, group, 0))) {
            goto cleanup;
        }
        break;
    }

    /* source path */
    if ((rc = srpjson_get_path(srpds_name, mod->name, src_ds, &src_path))) {
        goto cleanup;
    }

    /* copy contents of source to target */
    if ((rc = srpjson_cp_path(srpds_name, trg_path, src_path))) {
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(trg_path);
    free(owner);
    free(group);
    free(src_path);
    return rc;
}

static int
srpds_json_candidate_modified(const struct lys_module *mod, int *modified)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    /* candidate DS file cannot exist */
    if ((rc = srpjson_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
        goto cleanup;
    }

    if (srpjson_file_exists(srpds_name, path)) {
        /* file exists so it is modified */
        *modified = 1;
    } else {
        *modified = 0;
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_json_candidate_reset(const struct lys_module *mod)
{
    int rc = SR_ERR_OK;
    char *path;

    if ((rc = srpjson_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
        return rc;
    }

    if ((unlink(path) == -1) && (errno != ENOENT)) {
        SRPLG_LOG_WRN(srpds_name, "Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return rc;
}

static int
srpds_json_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK, file_exists = 0;
    char *path = NULL;

    assert(mod && (owner || group || perm));

    /* get correct path to the datastore file */
    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        /* single file that must exist */
        file_exists = 1;
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* datastore file may not exist */
        file_exists = srpjson_file_exists(srpds_name, path);
        break;
    }

    /* update file permissions and owner */
    if (file_exists && (rc = srpjson_chmodown(srpds_name, path, owner, group, perm))) {
        goto cleanup;
    }

    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        /* no permission file */
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* volatile datastore permission file */
        free(path);
        if ((rc = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        /* update file permissions and owner */
        if ((rc = srpjson_chmodown(srpds_name, path, owner, group, perm))) {
            goto cleanup;
        }
        break;
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_json_access_get(const struct lys_module *mod, sr_datastore_t ds, char **owner, char **group, mode_t *perm)
{
    int rc = SR_ERR_OK, r;
    struct stat st;
    char *path;

    if (owner) {
        *owner = NULL;
    }
    if (group) {
        *group = NULL;
    }

    /* get correct path */
    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            return rc;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((rc = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
            return rc;
        }
        break;
    }

    /* stat */
    r = stat(path, &st);
    if (r == -1) {
        if (errno == EACCES) {
            SRPLG_LOG_ERR(srpds_name, "Learning \"%s\" permissions failed.", mod->name);
            rc = SR_ERR_UNAUTHORIZED;
        } else {
            SRPLG_LOG_ERR(srpds_name, "Stat of \"%s\" failed (%s).", path, strerror(errno));
            rc = SR_ERR_SYS;
        }
        free(path);
        return rc;
    }
    free(path);

    /* get owner */
    if (owner && (rc = srpjson_get_pwd(srpds_name, &st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (rc = srpjson_get_grp(srpds_name, &st.st_gid, group))) {
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
        *owner = NULL;
    }
    if (group) {
        free(*group);
        *group = NULL;
    }
    return rc;
}

static int
srpds_json_access_check(const struct lys_module *mod, sr_datastore_t ds, int *read, int *write)
{
    int rc = SR_ERR_OK;
    char *path;

    /* get correct path */
    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((rc = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }
        break;
    }

    /* check read */
    if (read) {
        if (eaccess(path, R_OK) == -1) {
            if (errno == EACCES) {
                *read = 0;
            } else {
                SRPLG_LOG_ERR(srpds_name, "Eaccess of \"%s\" failed (%s).", path, strerror(errno));
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
                SRPLG_LOG_ERR(srpds_name, "Eaccess of \"%s\" failed (%s).", path, strerror(errno));
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

static int
srpds_json_last_modif(const struct lys_module *mod, sr_datastore_t ds, struct timespec *mtime)
{
    int rc = SR_ERR_OK;
    char *path = NULL;
    struct stat st;

    if ((rc = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    if (stat(path, &st) == 0) {
        *mtime = st.st_mtim;
    } else if (errno == ENOENT) {
        /* the file may not exist */
        mtime->tv_sec = 0;
        mtime->tv_nsec = 0;
    } else {
        SRPLG_LOG_ERR(srpds_name, "Stat of \"%s\" failed (%s).", path, strerror(errno));
        rc = SR_ERR_SYS;
    }

cleanup:
    free(path);
    return rc;
}

const struct srplg_ds_s srpds_json = {
    .name = srpds_name,
    .install_cb = srpds_json_install,
    .uninstall_cb = srpds_json_uninstall,
    .init_cb = srpds_json_init,
    .store_cb = srpds_json_store,
    .recover_cb = srpds_json_recover,
    .load_cb = srpds_json_load,
    .copy_cb = srpds_json_copy,
    .candidate_modified_cb = srpds_json_candidate_modified,
    .candidate_reset_cb = srpds_json_candidate_reset,
    .access_set_cb = srpds_json_access_set,
    .access_get_cb = srpds_json_access_get,
    .access_check_cb = srpds_json_access_check,
    .last_modif_cb = srpds_json_last_modif,
};
