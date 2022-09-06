/**
 * @file ds_lyb.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief internal LYB datastore plugin
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

#ifdef SR_HAVE_INOTIFY
# include <sys/inotify.h>
#endif

#include <libyang/libyang.h>

#include "compat.h"
#include "common_lyb.h"
#include "sysrepo.h"

#define srpds_name "LYB DS file"  /**< plugin name */

static int srpds_lyb_load(const struct lys_module *mod, sr_datastore_t ds, const char **xpaths, uint32_t xpath_count,
        struct lyd_node **mod_data);

static int srpds_lyb_access_get(const struct lys_module *mod, sr_datastore_t ds, char **owner, char **group,
        mode_t *perm);

static int
srpds_lyb_store_(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_data, const char *owner,
        const char *group, mode_t perm, int make_backup)
{
    int rc = SR_ERR_OK;
    struct stat st;
    char *path = NULL, *bck_path = NULL;
    int fd = -1, backup = 0, creat = 0;

    /* get path */
    if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
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
        if (asprintf(&bck_path, "%s%s", path, SRLYB_FILE_BACKUP_SUFFIX) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup;
        }

        /* create backup file with same owner/group/perm */
        if ((fd = srlyb_open(bck_path, O_WRONLY | O_CREAT | O_EXCL, st.st_mode)) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Opening \"%s\" failed (%s).", bck_path, strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup;
        }
        backup = 1;
        if (fchown(fd, st.st_uid, st.st_gid) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Changing owner of \"%s\" failed (%s).", bck_path, strerror(errno));
            if ((errno == EACCES) || (errno == EPERM)) {
                rc = SR_ERR_UNAUTHORIZED;
            } else {
                rc = SR_ERR_INTERNAL;
            }
            goto cleanup;
        }

        /* close */
        close(fd);
        fd = -1;

        /* back up any existing file */
        if ((rc = srlyb_cp_path(srpds_name, bck_path, path))) {
            goto cleanup;
        }
    }

    if (perm) {
        /* try to create the file */
        fd = srlyb_open(path, O_WRONLY | O_CREAT | O_EXCL, perm);
        if (fd > 0) {
            creat = 1;
        }
    }
    if (fd == -1) {
        /* open existing file */
        fd = srlyb_open(path, O_WRONLY, perm);
    }
    if (fd == -1) {
        rc = srlyb_open_error(srpds_name, path);
        goto cleanup;
    }

    if (creat && (owner || group)) {
        /* change the owner of the created file */
        if ((rc = srlyb_chmodown(srpds_name, path, owner, group, 0))) {
            goto cleanup;
        }
    }

    /* print data */
    if (lyd_print_fd(fd, mod_data, LYD_LYB, LYD_PRINT_WITHSIBLINGS)) {
        srplyb_log_err_ly(srpds_name, LYD_CTX(mod_data));
        SRPLG_LOG_ERR(srpds_name, "Failed to store data into \"%s\".", path);
        rc = SR_ERR_INTERNAL;
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
 * @brief Initialize startup datastore file.
 *
 * @param[in] mod Module to initialize.
 * @param[in] owner Owner of the data, may be NULL.
 * @param[in] group Group of the data, may be NULL.
 * @param[in] perm Permissions of the data.
 * @return SR_ERR value.
 */
static int
srpds_lyb_init_startup(const struct lys_module *mod, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK;
    struct lyd_node *root = NULL;
    char *path = NULL;

    /* check whether the file does not exist */
    if ((rc = srlyb_get_path(srpds_name, mod->name, SR_DS_STARTUP, &path))) {
        goto cleanup;
    }
    if (srlyb_file_exists(srpds_name, path)) {
        SRPLG_LOG_ERR(srpds_name, "File \"%s\" already exists.", path);
        rc = SR_ERR_EXISTS;
        goto cleanup;
    }

    /* get default values */
    if (lyd_new_implicit_module(&root, mod, LYD_IMPLICIT_NO_STATE, NULL)) {
        srplyb_log_err_ly(srpds_name, mod->ctx);
        rc = SR_ERR_LY;
        goto cleanup;
    }

    /* print them into the startup file */
    if ((rc = srpds_lyb_store_(mod, SR_DS_STARTUP, root, owner, group, perm, 0))) {
        goto cleanup;
    }

cleanup:
    free(path);
    lyd_free_siblings(root);
    return rc;
}

static int
srpds_lyb_init(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK, fd = -1;
    char *path = NULL;

    assert(perm);

    /* startup data dir */
    if ((rc = srlyb_get_startup_dir(srpds_name, &path))) {
        return rc;
    }
    if (!srlyb_file_exists(srpds_name, path) && (rc = srlyb_mkpath(srpds_name, path, SRLYB_DIR_PERM))) {
        goto cleanup;
    }

    if (ds == SR_DS_STARTUP) {
        /* startup init */
        rc = srpds_lyb_init_startup(mod, owner, group, perm);
        goto cleanup;
    }

    /* get path to the perm file */
    free(path);
    if ((rc = srlyb_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* create the file with the correct permissions */
    if ((fd = srlyb_open(path, O_RDONLY | O_CREAT | O_EXCL, perm)) == -1) {
        rc = srlyb_open_error(srpds_name, path);
        goto cleanup;
    }

    /* update the owner/group of the file */
    if (owner || group) {
        if ((rc = srlyb_chmodown(srpds_name, path, owner, group, 0))) {
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
srpds_lyb_destroy(const struct lys_module *mod, sr_datastore_t ds)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    /* unlink data file */
    if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if ((unlink(path) == -1) && ((errno != ENOENT) || (ds == SR_DS_STARTUP))) {
        /* only startup is persistent and must always exist */
        SRPLG_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }

    if (ds == SR_DS_STARTUP) {
        /* done */
        goto cleanup;
    }

    /* unlink perm file */
    free(path);
    if ((rc = srlyb_get_perm_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }
    if (unlink(path) == -1) {
        SRPLG_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_lyb_store(const struct lys_module *mod, sr_datastore_t ds, const struct lyd_node *mod_data)
{
    mode_t perm = 0;
    int rc;
    char *path = NULL, *owner = NULL, *group = NULL;

    switch (ds) {
    case SR_DS_STARTUP:
        /* must exist */
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* get data file path */
        if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        if (srlyb_file_exists(srpds_name, path)) {
            /* file exists */
            break;
        }

        /* get the correct permissions to set for the new file */
        if ((rc = srpds_lyb_access_get(mod, ds, &owner, &group, &perm))) {
            goto cleanup;
        }
        break;
    }

    /* store */
    if ((rc = srpds_lyb_store_(mod, ds, mod_data, owner, group, perm, 1))) {
        goto cleanup;
    }

cleanup:
    free(path);
    free(owner);
    free(group);
    return rc;
}

static void
srpds_lyb_recover(const struct lys_module *mod, sr_datastore_t ds)
{
    char *path = NULL, *bck_path = NULL;
    struct lyd_node *mod_data = NULL;

    /* get path */
    if (srlyb_get_path(srpds_name, mod->name, ds, &path)) {
        goto cleanup;
    }

    /* check whether the file is valid */
    if (!srpds_lyb_load(mod, ds, NULL, 0, &mod_data)) {
        /* data are valid, nothing to do */
        goto cleanup;
    }

    if (ds == SR_DS_STARTUP) {
        /* there must be a backup file for startup data */
        SRPLG_LOG_WRN("Recovering \"%s\" startup data from a backup.", mod->name);

        /* generate the backup path */
        if (asprintf(&bck_path, "%s%s", path, SRLYB_FILE_BACKUP_SUFFIX) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
            goto cleanup;
        }

        /* restore the backup data, avoid changing permissions of the target file */
        if (srlyb_cp_path(srpds_name, path, bck_path)) {
            goto cleanup;
        }

        /* remove the backup file */
        if (unlink(bck_path) == -1) {
            SRPLG_LOG_ERR(srpds_name, "Unlinking \"%s\" failed (%s).", bck_path, strerror(errno));
            goto cleanup;
        }
    } else if (ds == SR_DS_RUNNING) {
        /* perform startup->running data file copy */
        SRPLG_LOG_WRN("Recovering \"%s\" running data from the startup data.", mod->name);

        /* generate the startup data file path */
        if (srlyb_get_path(srpds_name, mod->name, SR_DS_STARTUP, &bck_path)) {
            goto cleanup;
        }

        /* copy startup data to running */
        if (srlyb_cp_path(srpds_name, path, bck_path)) {
            goto cleanup;
        }
    } else {
        /* there is not much to do but remove the corrupted file */
        SRPLG_LOG_WRN("Recovering \"%s\" %s data by removing the corrupted data file.", mod->name, srlyb_ds2str(ds));

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
srpds_lyb_load(const struct lys_module *mod, sr_datastore_t ds, const char **UNUSED(xpaths), uint32_t UNUSED(xpath_count),
        struct lyd_node **mod_data)
{
    int rc = SR_ERR_OK, fd = -1;
    char *path = NULL;
    uint32_t parse_opts;

    *mod_data = NULL;

    /* prepare correct file path */
    if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    /* open fd */
    fd = srlyb_open(path, O_RDONLY, 0);
    if (fd == -1) {
        if (errno == ENOENT) {
            if (ds == SR_DS_CANDIDATE) {
                /* no candidate exists */
                rc = SR_ERR_NOT_FOUND;
                goto cleanup;
            } else if ((ds != SR_DS_STARTUP) || !strcmp(mod->name, "sysrepo")) {
                /* volatile DS data file may not exist */
                goto cleanup;
            }
        }

        rc = srlyb_open_error(srpds_name, path);
        goto cleanup;
    }

    /* set parse options */
    if (!strcmp(mod->name, "sysrepo")) {
        /* internal module, accept an update */
        parse_opts = LYD_PARSE_LYB_MOD_UPDATE | LYD_PARSE_ONLY | LYD_PARSE_STRICT | LYD_PARSE_ORDERED;
    } else {
        parse_opts = LYD_PARSE_ONLY | LYD_PARSE_STRICT | LYD_PARSE_ORDERED;
    }

    /* load the data */
    if (lyd_parse_data_fd(mod->ctx, fd, LYD_LYB, parse_opts, 0, mod_data)) {
        srplyb_log_err_ly(srpds_name, mod->ctx);
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

#ifdef SR_HAVE_INOTIFY

/**
 * @brief Mark outdated cached data for specific modules.
 *
 * @param[in] cache Cache to use.
 * @param[in] mods Array of modules.
 * @param[in] mod_count Count of @p mods.
 * @param[out] cache_update Whether any of the module data needs to be updated.
 * @return SR_ERR value.
 */
static int
srpds_lyb_running_load_cached_mods(struct srlyb_cache_conn_s *cache, const struct lys_module **mods, uint32_t mod_count,
        int *cache_update)
{
    struct srlyb_cache_mod_s *cmod;
    struct inotify_event event;
    struct timespec ts_timeout;
    char *path = NULL;
    uint32_t i, j;
    void *mem;
    int r, rc = SR_ERR_OK;

    /* init timeout to 1s */
    clock_gettime(CLOCK_REALTIME, &ts_timeout);
    ++ts_timeout.tv_sec;

    /* MODS LOCK */
    if ((r = pthread_mutex_timedlock(&cache->lock, &ts_timeout))) {
        SRPLG_LOG_ERR(srpds_name, "Cache mods lock failed (%s).", strerror(r));
        return SR_ERR_SYS;
    }

    /* check for inotify changes of module data */
    while (read(cache->inot_fd, &event, sizeof event) != -1) {
        assert(!event.len && (event.mask == IN_MODIFY));

        /* find the affected module */
        for (j = 0; j < cache->mod_count; ++j) {
            if (cache->mods[j].inot_watch == event.wd) {
                cache->mods[j].current = 0;
                break;
            }
        }
        assert(j < cache->mod_count);
    }
    if (errno != EAGAIN) {
        SRPLG_LOG_ERR(srpds_name, "Inotify read failed (%s).", strerror(errno));
        rc = SR_ERR_SYS;
        goto cleanup_unlock;
    }

    for (i = 0; i < mod_count; ++i) {
        /* find entry for each module */
        cmod = NULL;
        for (j = 0; j < cache->mod_count; ++j) {
            if (cache->mods[j].mod == mods[i]) {
                cmod = &cache->mods[j];
                break;
            }
        }
        if (!cmod) {
            /* create an entry for this module */
            mem = realloc(cache->mods, (j + 1) * sizeof *cache->mods);
            if (!mem) {
                SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
                rc = SR_ERR_NO_MEMORY;
                goto cleanup_unlock;
            }
            cache->mods = mem;

            cmod = &cache->mods[j];
            memset(cmod, 0, sizeof *cmod);
            ++cache->mod_count;

            cmod->mod = mods[i];
            cmod->inot_watch = -1;
            cmod->current = 1;
        }

        if (cmod->inot_watch == -1) {
            /* prepare correct file path */
            free(path);
            if ((rc = srlyb_get_path(srpds_name, mods[i]->name, SR_DS_RUNNING, &path))) {
                goto cleanup_unlock;
            }

            /* create a watch for the module data file */
            cmod->inot_watch = inotify_add_watch(cache->inot_fd, path, IN_MODIFY);
            if (cmod->inot_watch == -1) {
                if (errno != ENOENT) {
                    SRPLG_LOG_ERR(srpds_name, "Inotify_add_watch failed (%s).", strerror(errno));
                    rc = SR_ERR_SYS;
                    goto cleanup_unlock;
                } /* else no data so consider them current */
            } else {
                /* some data exist */
                cmod->current = 0;
            }
        }

        if (!cmod->current) {
            /* module data in the cache need to be updated first */
            *cache_update = 1;
        }
    }

cleanup_unlock:
    /* MODS UNLOCK */
    pthread_mutex_unlock(&cache->lock);

    free(path);
    return rc;
}

static int
srpds_lyb_running_load_cached(sr_cid_t cid, const struct lys_module **mods, uint32_t mod_count,
        const struct lyd_node **data)
{
    struct srlyb_cache_conn_s *cache = NULL;
    struct timespec ts_timeout;
    uint32_t i;
    void *mem;
    int r, rc = SR_ERR_OK, cache_update = 0;

    /* init timeout to 1s */
    clock_gettime(CLOCK_REALTIME, &ts_timeout);
    ++ts_timeout.tv_sec;

    /* CACHE READ LOCK */
    if ((r = pthread_rwlock_timedrdlock(&data_cache.lock, &ts_timeout))) {
        SRPLG_LOG_ERR(srpds_name, "Cache read lock failed (%s).", strerror(r));
        rc = SR_ERR_SYS;
        goto cleanup;
    }

    /* find the connection cache */
    for (i = 0; i < data_cache.cache_count; ++i) {
        if (data_cache.caches[i].cid == cid) {
            cache = &data_cache.caches[i];
            break;
        }
    }
    if (!cache) {
        /* CACHE UNLOCK */
        pthread_rwlock_unlock(&data_cache.lock);

        /* CACHE WRITE LOCK */
        if ((r = pthread_rwlock_timedwrlock(&data_cache.lock, &ts_timeout))) {
            SRPLG_LOG_ERR(srpds_name, "Cache read lock failed (%s).", strerror(r));
            rc = SR_ERR_SYS;
            goto cleanup;
        }

        /* a new cache may have been added in the meantime */
        i = data_cache.cache_count;

        /* create cache for this connection */
        mem = realloc(data_cache.caches, (i + 1) * sizeof *data_cache.caches);
        if (!mem) {
            SRPLG_LOG_ERR(srpds_name, "Memory allocation failed.");
            rc = SR_ERR_NO_MEMORY;
            goto cleanup_unlock;
        }
        data_cache.caches = mem;

        cache = &data_cache.caches[i];
        memset(cache, 0, sizeof *cache);
        ++data_cache.cache_count;

        cache->cid = cid;
        if ((r = pthread_mutex_init(&cache->lock, NULL))) {
            SRPLG_LOG_ERR(srpds_name, "Initializing RW lock failed (%s).", strerror(r));
            rc = SR_ERR_SYS;
            goto cleanup_unlock;
        }
        cache->inot_fd = inotify_init1(IN_NONBLOCK);
        if (cache->inot_fd == -1) {
            SRPLG_LOG_ERR(srpds_name, "Inotify_init failed (%s).", strerror(errno));
            rc = SR_ERR_SYS;
            goto cleanup_unlock;
        }

        /* CACHE UNLOCK */
        pthread_rwlock_unlock(&data_cache.lock);

        /* CACHE READ LOCK */
        if ((r = pthread_rwlock_timedrdlock(&data_cache.lock, &ts_timeout))) {
            SRPLG_LOG_ERR(srpds_name, "Cache read lock failed (%s).", strerror(r));
            rc = SR_ERR_SYS;
            goto cleanup;
        }

        /* caches could have been realloc'd */
        cache = &data_cache.caches[i];
    }

    /* check module data */
    rc = srpds_lyb_running_load_cached_mods(cache, mods, mod_count, &cache_update);

cleanup_unlock:
    /* CACHE UNLOCK */
    pthread_rwlock_unlock(&data_cache.lock);

cleanup:
    if (!rc) {
        if (cache_update) {
            /* cache needs to be updated first */
            rc = SR_ERR_OPERATION_FAILED;
        } else {
            *data = cache->data;
        }
    }
    return rc;
}

static int
srpds_lyb_running_update_cached(sr_cid_t cid, const struct lys_module **UNUSED(mods), uint32_t UNUSED(mod_count))
{
    struct srlyb_cache_conn_s *cache = NULL;
    struct srlyb_cache_mod_s *cmod;
    struct lyd_node *mod_data;
    uint32_t i;
    int rc = SR_ERR_OK;

    /* find the connection cache */
    for (i = 0; i < data_cache.cache_count; ++i) {
        if (data_cache.caches[i].cid == cid) {
            cache = &data_cache.caches[i];
            break;
        }
    }
    assert(cache);

    for (i = 0; i < cache->mod_count; ++i) {
        cmod = &cache->mods[i];
        if (cmod->current) {
            /* module data in the cache are current */
            continue;
        }

        /* remove old data */
        mod_data = srlyb_module_data_unlink(&cache->data, cmod->mod);
        lyd_free_siblings(mod_data);

        /* need to actually load the data */
        if ((rc = srpds_lyb_load(cmod->mod, SR_DS_RUNNING, NULL, 0, &mod_data))) {
            goto cleanup;
        }
        if (mod_data) {
            lyd_insert_sibling(cache->data, mod_data, &cache->data);
        }

        /* data now current */
        cmod->current = 1;
    }

cleanup:
    return rc;
}

static void
srpds_lyb_running_flush_cached(sr_cid_t cid)
{
    struct srlyb_cache_conn_s *cache = NULL;
    struct timespec ts_timeout;
    uint32_t i;
    int r;

    /* init timeout to 1s */
    clock_gettime(CLOCK_REALTIME, &ts_timeout);
    ++ts_timeout.tv_sec;

    /* CACHE WRITE LOCK */
    if ((r = pthread_rwlock_timedwrlock(&data_cache.lock, &ts_timeout))) {
        SRPLG_LOG_ERR(srpds_name, "Cache write lock failed (%s).", strerror(r));
        return;
    }

    /* find the connection cache */
    for (i = 0; i < data_cache.cache_count; ++i) {
        if (data_cache.caches[i].cid == cid) {
            cache = &data_cache.caches[i];
            break;
        }
    }
    if (!cache) {
        goto cleanup;
    }

    /* free the connection cache */
    lyd_free_siblings(cache->data);
    free(cache->mods);
    pthread_mutex_destroy(&cache->lock);
    close(cache->inot_fd);

    /* consolidate the cache */
    --data_cache.cache_count;
    if (i < data_cache.cache_count) {
        SRPLG_LOG_ERR(srpds_name, "arg1 %p, arg2 %p, arg3 %u", data_cache.caches + i, data_cache.caches + i + 1, (data_cache.cache_count - i) * sizeof *data_cache.caches);
        memmove(data_cache.caches + i, data_cache.caches + i + 1, (data_cache.cache_count - i) * sizeof *data_cache.caches);
    } else if (!data_cache.cache_count) {
        free(data_cache.caches);
        data_cache.caches = NULL;
    }

cleanup:
    /* CACHE UNLOCK */
    pthread_rwlock_unlock(&data_cache.lock);
}

#endif

static int
srpds_lyb_copy(const struct lys_module *mod, sr_datastore_t trg_ds, sr_datastore_t src_ds)
{
    int rc = SR_ERR_OK, fd = -1;
    char *src_path = NULL, *trg_path = NULL, *owner = NULL, *group = NULL;
    mode_t perm = 0;

    /* target path */
    if ((rc = srlyb_get_path(srpds_name, mod->name, trg_ds, &trg_path))) {
        goto cleanup;
    }

    switch (trg_ds) {
    case SR_DS_STARTUP:
        /* must exist */
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if (srlyb_file_exists(srpds_name, trg_path)) {
            /* file exists */
            break;
        }

        /* get the correct permissions to set for the new file */
        if ((rc = srpds_lyb_access_get(mod, trg_ds, &owner, &group, &perm))) {
            goto cleanup;
        }

        /* create the target file with the correct permissions */
        if ((fd = srlyb_open(trg_path, O_WRONLY | O_CREAT | O_EXCL, perm)) == -1) {
            rc = srlyb_open_error(srpds_name, trg_path);
            goto cleanup;
        }

        /* change the owner/group of the new file */
        if ((rc = srlyb_chmodown(srpds_name, trg_path, owner, group, 0))) {
            goto cleanup;
        }
        break;
    }

    /* source path */
    if ((rc = srlyb_get_path(srpds_name, mod->name, src_ds, &src_path))) {
        goto cleanup;
    }

    /* copy contents of source to target */
    if ((rc = srlyb_cp_path(srpds_name, trg_path, src_path))) {
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
srpds_lyb_update_differ(const struct lys_module *old_mod, const struct lyd_node *old_mod_data,
        const struct lys_module *new_mod, const struct lyd_node *new_mod_data, int *differ)
{
    const struct lys_module *mod_iter, *mod_iter2;
    uint32_t idx = 0;
    LY_ARRAY_COUNT_TYPE u;
    LY_ERR lyrc;

    if (old_mod) {
        /* first check whether any modules augmenting/deviating this module were not removed or updated, in that
         * case LYB metadata have changed and the data must be stored whether they differ or not */
        while ((mod_iter = ly_ctx_get_module_iter(old_mod->ctx, &idx))) {
            if (!mod_iter->implemented) {
                /* we need data of only implemented modules */
                continue;
            }

            mod_iter2 = ly_ctx_get_module_implemented(new_mod->ctx, mod_iter->name);
            if (mod_iter2 && (mod_iter->revision == mod_iter2->revision)) {
                /* module was not removed nor updated, irrelevant */
                continue;
            }

            /* deviates */
            LY_ARRAY_FOR(old_mod->deviated_by, u) {
                if (old_mod->deviated_by[u] == mod_iter) {
                    *differ = 1;
                    return SR_ERR_OK;
                }
            }

            /* augments */
            LY_ARRAY_FOR(old_mod->augmented_by, u) {
                if (old_mod->augmented_by[u] == mod_iter) {
                    *differ = 1;
                    return SR_ERR_OK;
                }
            }
        }
    }

    /* check for data difference */
    lyrc = lyd_compare_siblings(new_mod_data, old_mod_data, LYD_COMPARE_FULL_RECURSION | LYD_COMPARE_DEFAULTS);
    if (lyrc && (lyrc != LY_ENOT)) {
        srplyb_log_err_ly(srpds_name, new_mod->ctx);
        return SR_ERR_LY;
    }

    if (lyrc == LY_ENOT) {
        *differ = 1;
    } else {
        *differ = 0;
    }
    return SR_ERR_OK;
}

static int
srpds_lyb_candidate_modified(const struct lys_module *mod, int *modified)
{
    int rc = SR_ERR_OK;
    char *path = NULL;

    /* candidate DS file cannot exist */
    if ((rc = srlyb_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
        goto cleanup;
    }

    if (srlyb_file_exists(srpds_name, path)) {
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
srpds_lyb_candidate_reset(const struct lys_module *mod)
{
    int rc = SR_ERR_OK;
    char *path;

    if ((rc = srlyb_get_path(srpds_name, mod->name, SR_DS_CANDIDATE, &path))) {
        return rc;
    }

    if ((unlink(path) == -1) && (errno != ENOENT)) {
        SRPLG_LOG_WRN("Failed to unlink \"%s\" (%s).", path, strerror(errno));
    }
    free(path);

    return rc;
}

static int
srpds_lyb_access_set(const struct lys_module *mod, sr_datastore_t ds, const char *owner, const char *group, mode_t perm)
{
    int rc = SR_ERR_OK, file_exists = 0;
    char *path = NULL;

    assert(mod && (owner || group || perm));

    /* get correct path to the datastore file */
    if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    switch (ds) {
    case SR_DS_STARTUP:
        /* single file that must exist */
        file_exists = 1;
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* datastore file may not exist */
        file_exists = srlyb_file_exists(srpds_name, path);
        break;
    }

    /* update file permissions and owner */
    if (file_exists && (rc = srlyb_chmodown(srpds_name, path, owner, group, perm))) {
        goto cleanup;
    }

    switch (ds) {
    case SR_DS_STARTUP:
        /* no permission file */
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        /* volatile datastore permission file */
        free(path);
        if ((rc = srlyb_get_perm_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }

        /* update file permissions and owner */
        if ((rc = srlyb_chmodown(srpds_name, path, owner, group, perm))) {
            goto cleanup;
        }
        break;
    }

cleanup:
    free(path);
    return rc;
}

static int
srpds_lyb_access_get(const struct lys_module *mod, sr_datastore_t ds, char **owner, char **group, mode_t *perm)
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
        if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
            return rc;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((rc = srlyb_get_perm_path(srpds_name, mod->name, ds, &path))) {
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
    if (owner && (rc = srlyb_get_pwd(srpds_name, &st.st_uid, owner))) {
        goto error;
    }

    /* get group */
    if (group && (rc = srlyb_get_grp(srpds_name, &st.st_gid, group))) {
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
srpds_lyb_access_check(const struct lys_module *mod, sr_datastore_t ds, int *read, int *write)
{
    int rc = SR_ERR_OK;
    char *path;

    /* get correct path */
    switch (ds) {
    case SR_DS_STARTUP:
        if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
            goto cleanup;
        }
        break;
    case SR_DS_RUNNING:
    case SR_DS_CANDIDATE:
    case SR_DS_OPERATIONAL:
        if ((rc = srlyb_get_perm_path(srpds_name, mod->name, ds, &path))) {
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
srpds_lyb_last_modif(const struct lys_module *mod, sr_datastore_t ds, struct timespec *mtime)
{
    int rc = SR_ERR_OK;
    char *path = NULL;
    struct stat buf;

    if ((rc = srlyb_get_path(srpds_name, mod->name, ds, &path))) {
        goto cleanup;
    }

    if (stat(path, &buf) == 0) {
        mtime->tv_sec = buf.st_mtime;
        mtime->tv_nsec = 0;
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

const struct srplg_ds_s srpds_lyb = {
    .name = srpds_name,
    .init_cb = srpds_lyb_init,
    .destroy_cb = srpds_lyb_destroy,
    .store_cb = srpds_lyb_store,
    .recover_cb = srpds_lyb_recover,
    .load_cb = srpds_lyb_load,
#ifdef SR_HAVE_INOTIFY
    .running_load_cached_cb = srpds_lyb_running_load_cached,
    .running_update_cached_cb = srpds_lyb_running_update_cached,
    .running_flush_cached_cb = srpds_lyb_running_flush_cached,
#else
    .running_load_cached_cb = NULL,
    .running_update_cached_cb = NULL,
    .running_flush_cached_cb = NULL,
#endif
    .copy_cb = srpds_lyb_copy,
    .update_differ_cb = srpds_lyb_update_differ,
    .candidate_modified_cb = srpds_lyb_candidate_modified,
    .candidate_reset_cb = srpds_lyb_candidate_reset,
    .access_set_cb = srpds_lyb_access_set,
    .access_get_cb = srpds_lyb_access_get,
    .access_check_cb = srpds_lyb_access_check,
    .last_modif_cb = srpds_lyb_last_modif,
};
