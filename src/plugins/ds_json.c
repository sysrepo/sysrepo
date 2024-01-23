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

static sr_error_info_t *srpds_json_load(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths,
        uint32_t xpath_count, void *plg_data, struct lyd_node **mod_data);

static sr_error_info_t * srpds_json_access_get(const struct lys_module *mod, sr_datastore_t ds, void *plg_data,
        char **owner, char **group, mode_t *perm);

static sr_error_info_t *
srpds_json_store_(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_data, const char *owner,
        const char *group, mode_t perm, int make_backup)
{
    sr_error_info_t *err_info = NULL;
    struct stat st;
    char *path = NULL, *bck_path = NULL;
    int fd = -1, backup = 0, creat = 0;
    uint32_t print_opts;
    off_t size;

    /* get path */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    if (make_backup && (ds == SR_DS_STARTUP)) {
        /* get original file perms */
        if (stat(path, &st) == -1) {
            if (errno == EACCES) {
                srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_UNAUTHORIZED, "Learning \"%s\" permissions failed.",
                        mod->name);
            } else {
                srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Stat of \"%s\" failed (%s).", path,
                        strerror(errno));
            }
            goto cleanup;
        }

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SRPJSON_FILE_BACKUP_SUFFIX) == -1) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
            goto cleanup;
        }

        /* create backup file with same permissions (not owner/group because it may be different and this process
         * not has permissions to use that owner/group) */
        if ((fd = srpjson_open(srpds_name, bck_path, O_WRONLY | O_CREAT | O_EXCL, st.st_mode)) == -1) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Opening \"%s\" failed (%s).", bck_path,
                    strerror(errno));
            goto cleanup;
        }
        backup = 1;

        /* close */
        close(fd);
        fd = -1;

        /* back up any existing file */
        if ((err_info = srpjson_cp_path(srpds_name, bck_path, path))) {
            goto cleanup;
        }
    }

    if (perm) {
        /* try to create the file */
        fd = srpjson_open(srpds_name, path, O_WRONLY | O_CREAT | O_EXCL, perm);
        if (fd > 0) {
            creat = 1;
        }
    }
    if (fd == -1) {
        /* open existing file */
        fd = srpjson_open(srpds_name, path, O_WRONLY, perm);
    }
    if (fd == -1) {
        err_info = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    if (creat && (owner || group)) {
        /* change the owner of the created file */
        if ((err_info = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
            goto cleanup;
        }
    }

    /* print data */
    print_opts = LYD_PRINT_SHRINK | LYD_PRINT_WITHSIBLINGS | LYD_PRINT_KEEPEMPTYCONT | LYD_PRINT_WD_IMPL_TAG;
    if (lyd_print_fd(fd, mod_data, LYD_JSON, print_opts)) {
        err_info = srpjson_log_err_ly(srpds_name, LYD_CTX(mod_data));
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_INTERNAL, "Failed to store data into \"%s\".", path);
        goto cleanup;
    }

    /* truncate the file to the exact size (to get rid of possible following old data) */
    if ((size = lseek(fd, 0, SEEK_CUR)) == -1) {
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Failed to get the size of \"%s\" (%s).", path,
                strerror(errno));
        goto cleanup;
    }
    if (ftruncate(fd, size) == -1) {
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Failed to truncate \"%s\" (%s).", path,
                strerror(errno));
        goto cleanup;
    }

cleanup:
    /* delete the backup file */
    if (backup && (unlink(bck_path) == -1)) {
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Failed to remove backup \"%s\" (%s).", bck_path,
                strerror(errno));
    }

    if (fd > -1) {
        close(fd);
    }
    free(path);
    free(bck_path);
    return err_info;
}

/**
 * @brief Initialize persistent datastore file.
 *
 * @param[in] mod Module to initialize.
 * @param[in] ds Datastore.
 * @param[in] owner Owner of the data, may be NULL.
 * @param[in] group Group of the data, may be NULL.
 * @param[in] perm Permissions of the data.
 * @param[in] plg_data Plugin data.
 * @return SR_ERR value.
 */
static sr_error_info_t *
srpds_json_install_persistent(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    /* check whether the file does not exist */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if (srpjson_file_exists(srpds_name, path)) {
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_EXISTS, "File \"%s\" already exists.", path);
        goto cleanup;
    }

    /* print empty file to store permissions */
    if ((err_info = srpds_json_store_(mod, ds, NULL, owner, group, perm, 0))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_install(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm,
        void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    char *path = NULL;

    assert(perm);

    /* startup data dir */
    if ((err_info = srpjson_get_startup_dir(srpds_name, &path))) {
        return err_info;
    }
    if (!srpjson_file_exists(srpds_name, path) && (err_info = srpjson_mkpath(srpds_name, path, SRPJSON_DIR_PERM))) {
        goto cleanup;
    }

    if ((ds == SR_DS_STARTUP) || (ds == SR_DS_FACTORY_DEFAULT)) {
        /* persistent DS file install */
        err_info = srpds_json_install_persistent(mod, ds, owner, group, perm, NULL);
        goto cleanup;
    }

    /* get path to the perm file */
    free(path);
    if ((err_info = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* create the file with the correct permissions */
    if ((fd = srpjson_open(srpds_name, path, O_RDONLY | O_CREAT | O_EXCL, perm)) == -1) {
        err_info = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    /* update the owner/group of the file */
    if (owner || group) {
        if ((err_info = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
            goto cleanup;
        }
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_uninstall(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    /* unlink data file */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
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
    if ((err_info = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if (unlink(path) == -1) {
        SRPLG_LOG_WRN(srpds_name, "Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }

cleanup:
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_init(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    char *owner = NULL, *group = NULL, *path = NULL;
    mode_t perm;

    if (ds != SR_DS_RUNNING) {
        /* startup and factory-default are persistent and candidate with operational exists only if modified */
        return NULL;
    }

    if (!srpjson_module_has_data(mod, 0)) {
        /* no data, do not create the file */
        return NULL;
    }

    /* get owner/group/perms of the datastore file */
    if ((err_info = srpds_json_access_get(mod, ds, NULL, &owner, &group, &perm))) {
        goto cleanup;
    }

    /* get path to the file */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* create the file with the correct permissions */
    if ((fd = srpjson_open(srpds_name, path, O_WRONLY | O_CREAT | O_EXCL, perm)) == -1) {
        err_info = srpjson_open_error(srpds_name, path);
        goto cleanup;
    }

    /* print empty JSON file */
    if (lyd_print_fd(fd, NULL, LYD_JSON, LYD_PRINT_SHRINK)) {
        err_info = srpjson_log_err_ly(srpds_name, NULL);
        goto cleanup;
    }

    /* update the owner/group of the file */
    if ((err_info = srpjson_chmodown(srpds_name, path, owner, group, 0))) {
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(owner);
    free(group);
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_conn_init(sr_conn_ctx_t *UNUSED(conn), void **UNUSED(plg_data))
{
    return NULL;
}

static void
srpds_json_conn_destroy(sr_conn_ctx_t *UNUSED(conn), void *UNUSED(plg_data))
{
}

static sr_error_info_t *
srpds_json_store(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *UNUSED(mod_diff),
        const struct lyd_node *mod_data, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    mode_t perm = 0;
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
        if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        if (srpjson_file_exists(srpds_name, path)) {
            /* file exists */
            break;
        }

        /* get the correct permissions to set for the new file (not owner/group because we may not have permissions to set them) */
        if ((err_info = srpds_json_access_get(mod, ds, NULL, NULL, NULL, &perm))) {
            goto cleanup;
        }
        break;
    }

    /* store */
    if ((err_info = srpds_json_store_(mod, ds, mod_data, NULL, NULL, perm, 1))) {
        goto cleanup;
    }

cleanup:
    free(path);
    return err_info;
}

static void
srpds_json_recover(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL, *bck_path = NULL;
    struct lyd_node *mod_data = NULL;

    /* get path */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* check whether the file is valid */
    if (!(err_info = srpds_json_load(mod, ds, NULL, 0, NULL, &mod_data))) {
        /* data are valid, nothing to do */
        goto cleanup;
    }
    srplg_errinfo_free(&err_info);

    if (ds == SR_DS_STARTUP) {
        /* there must be a backup file for startup data */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" startup data from a backup.", mod->name);

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SRPJSON_FILE_BACKUP_SUFFIX) == -1) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_NO_MEMORY, "Memory allocation failed.");
            goto cleanup;
        }

        /* restore the backup data, avoid changing permissions of the target file */
        if ((err_info = srpjson_cp_path(srpds_name, path, bck_path))) {
            goto cleanup;
        }

        /* remove the backup file */
        if (unlink(bck_path) == -1) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Unlinking \"%s\" failed (%s).", bck_path, strerror(errno));
            goto cleanup;
        }
    } else if (ds == SR_DS_RUNNING) {
        /* perform startup->running data file copy */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" running data from the startup data.", mod->name);

        /* generate the startup data file path */
        if ((err_info = srpjson_get_path(srpds_name, mod->name, SR_DS_STARTUP, &bck_path))) {
            goto cleanup;
        }

        /* copy startup data to running */
        if ((err_info = srpjson_cp_path(srpds_name, path, bck_path))) {
            goto cleanup;
        }
    } else {
        /* there is not much to do but remove the corrupted file */
        SRPLG_LOG_WRN(srpds_name, "Recovering \"%s\" %s data by removing the corrupted data file.", mod->name,
                srpjson_ds2str(ds));

        if (unlink(path) == -1) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Unlinking \"%s\" failed (%s).", path,
                    strerror(errno));
            goto cleanup;
        }
    }

cleanup:
    free(path);
    free(bck_path);
    lyd_free_all(mod_data);
    srplg_errinfo_free(&err_info);
}

static sr_error_info_t *
srpds_json_load(const struct lys_module *mod, sr_datastore_t ds, const char **UNUSED(xpaths), uint32_t UNUSED(xpath_count),
        void *UNUSED(plg_data), struct lyd_node **mod_data)
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    char *path = NULL;
    uint32_t parse_opts;

    *mod_data = NULL;

    /* prepare correct file path */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* open fd */
    fd = srpjson_open(srpds_name, path, O_RDONLY, 0);
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

        err_info = srpjson_open_error(srpds_name, path);
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
        err_info = srpjson_log_err_ly(srpds_name, mod->ctx);
        goto cleanup;
    }

cleanup:
    if (fd > -1) {
        close(fd);
    }
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_copy(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    int fd = -1;
    char *src_path = NULL, *trg_path = NULL, *owner = NULL, *group = NULL;
    mode_t perm = 0;

    /* target path */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, trg_ds, &trg_path))) {
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
        if ((err_info = srpds_json_access_get(mod, trg_ds, NULL, &owner, &group, &perm))) {
            goto cleanup;
        }

        /* create the target file with the correct permissions */
        if ((fd = srpjson_open(srpds_name, trg_path, O_WRONLY | O_CREAT | O_EXCL, perm)) == -1) {
            err_info = srpjson_open_error(srpds_name, trg_path);
            goto cleanup;
        }

        /* change the owner/group of the new file */
        if ((err_info = srpjson_chmodown(srpds_name, trg_path, owner, group, 0))) {
            goto cleanup;
        }
        break;
    }

    /* source path */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, src_ds, &src_path))) {
        goto cleanup;
    }

    /* copy contents of source to target */
    if ((err_info = srpjson_cp_path(srpds_name, trg_path, src_path))) {
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
    return err_info;
}

static sr_error_info_t *
srpds_json_candidate_modified(const struct lys_module *mod, void *UNUSED(plg_data), int *modified)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;

    /* candidate DS file cannot exist */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
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
    return err_info;
}

static sr_error_info_t *
srpds_json_candidate_reset(const struct lys_module *mod, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if ((err_info = srpjson_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
        return err_info;
    }

    if ((unlink(path) == -1) && (errno != ENOENT)) {
        SRPLG_LOG_WRN(srpds_name, "Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return NULL;
}

static sr_error_info_t *
srpds_json_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group,
        mode_t perm, void *UNUSED(plg_data))
{
    sr_error_info_t *err_info = NULL;
    int file_exists = 0;
    char *path = NULL;

    assert(mod && (owner || group || perm));

    /* get correct path to the datastore file */
    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
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
    if (file_exists && (err_info = srpjson_chmodown(srpds_name, path, owner, group, perm))) {
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
        if ((err_info = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        /* update file permissions and owner */
        if ((err_info = srpjson_chmodown(srpds_name, path, owner, group, perm))) {
            goto cleanup;
        }
        break;
    }

cleanup:
    free(path);
    return err_info;
}

static sr_error_info_t *
srpds_json_access_get(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data), char **owner, char **group,
        mode_t *perm)
{
    sr_error_info_t *err_info = NULL;
    int r;
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
        if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            return err_info;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((err_info = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
            return err_info;
        }
        break;
    }

    /* stat */
    r = stat(path, &st);
    if (r == -1) {
        if (errno == EACCES) {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_UNAUTHORIZED, "Learning \"%s\" permissions failed.",
                    mod->name);
        } else {
            srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Stat of \"%s\" failed (%s).", path, strerror(errno));
        }
        free(path);
        return err_info;
    }
    free(path);

    /* get owner */
    if (owner && (err_info = srpjson_get_pwd(srpds_name, &st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (err_info = srpjson_get_grp(srpds_name, &st.st_gid, group))) {
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
        *owner = NULL;
    }
    if (group) {
        free(*group);
        *group = NULL;
    }
    return err_info;
}

static sr_error_info_t *
srpds_json_access_check(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data), int *read, int *write)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    /* get correct path */
    switch (ds) {
    case SR_DS_STARTUP:
    case SR_DS_FACTORY_DEFAULT:
        if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((err_info = srpjson_get_perm_path(srpds_name, mod->name, ds, &path))) {
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
                srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Eaccess of \"%s\" failed (%s).", path,
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
                srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Eaccess of \"%s\" failed (%s).", path,
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

static sr_error_info_t *
srpds_json_last_modif(const struct lys_module *mod, sr_datastore_t ds, void *UNUSED(plg_data), struct timespec *mtime)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    struct stat st;

    if ((err_info = srpjson_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    if (stat(path, &st) == 0) {
        *mtime = st.st_mtim;
    } else if (errno == ENOENT) {
        /* the file may not exist */
        mtime->tv_sec = 0;
        mtime->tv_nsec = 0;
    } else {
        srplg_log_errinfo(&err_info, srpds_name, NULL, SR_ERR_SYS, "Stat of \"%s\" failed (%s).", path, strerror(errno));
    }

cleanup:
    free(path);
    return err_info;
}

const struct srplg_ds_s srpds_json = {
    .name = srpds_name,
    .install_cb = srpds_json_install,
    .uninstall_cb = srpds_json_uninstall,
    .init_cb = srpds_json_init,
    .conn_init_cb = srpds_json_conn_init,
    .conn_destroy_cb = srpds_json_conn_destroy,
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
