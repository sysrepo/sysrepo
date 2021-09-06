/**
 * @file shm_main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines
 *
 * @copyright
 * Copyright (c) 2018 - 2021 Deutsche Telekom AG.
 * Copyright (c) 2018 - 2021 CESNET, z.s.p.o.
 *
 * This source code is licensed under BSD 3-Clause License (the "License").
 * You may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     https://opensource.org/licenses/BSD-3-Clause
 */

#define _GNU_SOURCE

#include "shm.h"

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "config.h"
#include "log.h"
#include "plugins_datastore.h"
#include "sysrepo.h"

/**
 * @brief Item holding information about active connections owned by this process.
 */
typedef struct _conn_list_entry {
    struct _conn_list_entry *_next;
    sr_cid_t cid;
    int lock_fd;
} sr_conn_list_item;

/**
 * @brief Linked list of all active connections in this process.
 *
 * Each sysrepo connection maintains a POSIX advisory lock on its lockfile. These
 * locks allow other sysrepo processes to validate if a tracked connection is
 * still alive. However a process closing ANY file descriptor to a lockfile on
 * which it holds an advisory lock results in the lock being immediately
 * released. To avoid this condition this linked list tracks all open connections
 * within the current process along with the open file descriptor used to create
 * the advisory lock. When testing for aliveness (sr_shmmain_conn_lock) this list
 * is checked first to see if the connection ID is owned by this process. Only
 * when that check fails will the lock test open (and later close) a file handle
 * to the lockfile for testing the lock. This list is used by the disconnect logic
 * to close the filehandle which releases the lock. Programs which do not cleanly
 * disconnect (eg crash) will have the lock removed automatcially as the
 * terminated process is cleaned up.
 */
static struct {
    sr_conn_list_item *head;
    pthread_mutex_t lock;
} conn_list = {.head = NULL, .lock = PTHREAD_MUTEX_INITIALIZER};

sr_error_info_t *
sr_shmmain_check_dirs(void)
{
    char *dir_path;
    sr_error_info_t *err_info = NULL;
    int ret;

    /* YANG module dir */
    if ((err_info = sr_path_yang_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        SR_ERRINFO_SYSERRPATH(&err_info, "access", dir_path);
        free(dir_path);
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* connection lock dir */
    if ((err_info = sr_path_conn_lockfile(0, &dir_path))) {
        return err_info;
    }
    if ((err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    return NULL;
}

sr_error_info_t *
sr_shmmain_createlock_open(int *shm_lock)
{
    sr_error_info_t *err_info = NULL;
    char *path;

    if (asprintf(&path, "%s/%s", sr_get_repo_path(), SR_MAIN_SHM_LOCK) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    *shm_lock = sr_open(path, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);

    if (*shm_lock == -1) {
        SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
    }
    free(path);
    return err_info;
}

sr_error_info_t *
sr_shmmain_createlock(int shm_lock)
{
    struct flock fl;
    int ret;
    sr_error_info_t *err_info = NULL;

    assert(shm_lock > -1);

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK;
    do {
        ret = fcntl(shm_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "fcntl");
        return err_info;
    }

    return NULL;
}

void
sr_shmmain_createunlock(int shm_lock)
{
    struct flock fl;

    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(shm_lock, F_SETLK, &fl) == -1) {
        assert(0);
    }
}

sr_error_info_t *
sr_shmmain_conn_check(sr_cid_t cid, int *conn_alive, pid_t *pid)
{
    sr_error_info_t *err_info = NULL;
    struct flock fl = {0};
    int fd, rc;
    char *path = NULL;
    sr_conn_list_item *ptr;

    assert(cid && conn_alive);

    /* CONN LIST LOCK */
    if ((err_info = sr_mlock(&conn_list.lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* If the connection is owned by this process a check using flock which
     * requires an open/close would release the lock. Check if the CID is a
     * connection owned by this process and return status before we do an
     * open().
     */
    if (conn_list.head) {
        for (ptr = conn_list.head; ptr; ptr = ptr->_next) {
            if (cid == ptr->cid) {
                /* alive connection of this process */
                *conn_alive = 1;
                if (pid) {
                    *pid = getpid();
                }

                /* CONN LIST UNLOCK */
                sr_munlock(&conn_list.lock);
                goto cleanup;
            }
        }
    }

    /* CONN LIST UNLOCK */
    sr_munlock(&conn_list.lock);

    /* open the file to test the lock */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        goto cleanup;
    }
    fd = sr_open(path, O_WRONLY, 0);
    if (fd == -1) {
        if (errno == ENOENT) {
            /* the file does not exist in which case there is no connection established */
            *conn_alive = 0;
            if (pid) {
                *pid = 0;
            }
            goto cleanup;
        }
        SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
        goto cleanup;
    }

    /* check the lock */
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; /* length of 0 is entire file */
    fl.l_type = F_WRLCK;
    rc = fcntl(fd, F_GETLK, &fl);
    /* Closing any FD to a lock file of a connection owned by this process will
     * immediately release the lock. When testing locks, we search conn_list
     * above to ensure we only open/close lock files owned by other processes. */
    close(fd);
    if (rc == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "flock");
        goto cleanup;
    }
    if (fl.l_type == F_UNLCK) {
        /* leftover unlocked file */
        *conn_alive = 0;
        if (pid) {
            *pid = 0;
        }

        /* delete the file */
        if (!unlink(path)) {
            /* print message, file was deleted */
            SR_LOG_WRN("Connection with CID %" PRIu32 " is dead.", cid);
        } else if (errno != ENOENT) {
            /* removing the file is subject to a (harmless) data race, account for it */
            SR_ERRINFO_SYSERRNO(&err_info, "unlink");
        }
    } else {
        /* we cannot get the lock, it must be held by a live connection */
        *conn_alive = 1;
        if (pid) {
            *pid = fl.l_pid;
        }
    }

cleanup:
    free(path);
    return err_info;
}

/**
 * @brief Open and lock a new connection lockfile.
 *
 * @param[in] cid CID of the lockfile.
 * @param[out] lock_fd Opened lockfile.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_conn_new_lockfile(sr_cid_t cid, int *lock_fd)
{
    sr_error_info_t *err_info = NULL;
    char *path = NULL;
    int fd = -1;
    struct flock fl = {0};
    char buf[64];

    /* open the connection lock file with the correct permissions */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        return err_info;
    }
    fd = sr_open(path, O_CREAT | O_RDWR, SR_CONN_LOCKFILE_PERM);
    if (fd == -1) {
        SR_ERRINFO_SYSERRPATH(&err_info, "open", path);
        goto cleanup;
    }

    /* Write the PID into the file for debug. The / helps identify if a
     * file is unexpectedly reused. */
    snprintf(buf, sizeof(buf) - 1, "/%ld\n", (long)getpid());
    write(fd, buf, strlen(buf));

    /* set an exclusive lock on the file */
    fl.l_whence = SEEK_SET;
    fl.l_start = 0;
    fl.l_len = 0; /* length of 0 is entire file */
    fl.l_type = F_WRLCK;

    /* this will fail if we end up reusing a CID while a lock is held on it */
    if (fcntl(fd, F_SETLK, &fl) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "flock");
        goto cleanup;
    }

cleanup:
    if (err_info) {
        if (fd > -1) {
            close(fd);
        }
    } else {
        *lock_fd = fd;
    }
    free(path);
    return err_info;
}

sr_error_info_t *
sr_shmmain_conn_list_add(sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    sr_conn_list_item *conn_item = NULL;
    int lock_fd = -1;

    /* open and lock the connection lockfile */
    if ((err_info = sr_shmmain_conn_new_lockfile(cid, &lock_fd))) {
        goto error;
    }

    /* allocate a new conn_list item for tracking this process connections */
    conn_item = calloc(1, sizeof *conn_item);
    if (!conn_item) {
        SR_ERRINFO_MEM(&err_info);
        goto error;
    }
    conn_item->cid = cid;
    conn_item->lock_fd = lock_fd;

    /* CONN LIST LOCK */
    if ((err_info = sr_mlock(&conn_list.lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        goto error;
    }

    /* insert at the head of the list */
    conn_item->_next = conn_list.head;
    conn_list.head = conn_item;

    /* CONN LIST UNLOCK */
    sr_munlock(&conn_list.lock);

    return NULL;

error:
    if (lock_fd > -1) {
        char *path;
        sr_error_info_t *err_info_2 = NULL;
        close(lock_fd);
        if ((err_info_2 = sr_path_conn_lockfile(cid, &path))) {
            sr_errinfo_free(&err_info_2);
        } else {
            unlink(path);
            free(path);
        }
    }
    free(conn_item);
    return err_info;
}

sr_error_info_t *
sr_shmmain_conn_list_del(sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    char *path;
    sr_conn_list_item *ptr, *prev;

    /* CONN LIST LOCK */
    if ((err_info = sr_mlock(&conn_list.lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        return err_info;
    }

    ptr = conn_list.head;
    prev = NULL;
    while (ptr) {
        if (cid == ptr->cid) {
            /* remove the entry from the list */
            if (!prev) {
                conn_list.head = ptr->_next;
            } else {
                prev->_next = ptr->_next;
            }

            /* cleanup local resources */
            if (ptr->lock_fd > 0) {
                /* closing ANY file descriptor to a locked file releases all the locks */
                close(ptr->lock_fd);
            } else {
                SR_ERRINFO_INT(&err_info);
            }
            free(ptr);
            break;
        }

        prev = ptr;
        ptr = ptr->_next;
    }

    /* CONN LIST UNLOCK */
    sr_munlock(&conn_list.lock);

    /* remove the lockfile as well */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        return err_info;
    }
    if (unlink(path)) {
        SR_ERRINFO_SYSERRNO(&err_info, "unlink");
    }
    free(path);

    return err_info;
}

sr_error_info_t *
sr_shmmain_ly_ctx_init(struct ly_ctx **ly_ctx)
{
    sr_error_info_t *err_info = NULL;

    /* libyang context init */
    if ((err_info = sr_ly_ctx_new(ly_ctx))) {
        return err_info;
    }

    /* load just the internal module */
    if (lys_parse_mem(*ly_ctx, sysrepo_yang, LYS_IN_YANG, NULL)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx);
        goto cleanup;
    }

    /* compile */
    if (ly_ctx_compile(*ly_ctx)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx);
        goto cleanup;
    }

cleanup:
    if (err_info) {
        ly_ctx_destroy(*ly_ctx);
        *ly_ctx = NULL;
    }
    return err_info;
}

sr_error_info_t *
sr_shmmain_files_startup2running(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    sr_mod_t *shm_mod;
    const struct lys_module *ly_mod;
    struct lyd_node *mod_data;
    struct srplg_ds_s *plg1, *plg2;
    int rc;
    uint32_t i;

    main_shm = SR_CONN_MAIN_SHM(conn);

    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);

        /* find LY module */
        ly_mod = ly_ctx_get_module_implemented(conn->ly_ctx, ((char *)main_shm) + shm_mod->name);
        assert(ly_mod);

        /* find DS plugins */
        if ((err_info = sr_ds_plugin_find(((char *)main_shm) + shm_mod->plugins[SR_DS_RUNNING], conn, &plg1))) {
            return err_info;
        }
        if ((err_info = sr_ds_plugin_find(((char *)main_shm) + shm_mod->plugins[SR_DS_STARTUP], conn, &plg2))) {
            return err_info;
        }

        if (plg1 == plg2) {
            /* same plugin, we can use copy callback */
            rc = plg1->copy_cb(ly_mod, SR_DS_RUNNING, SR_DS_STARTUP);
        } else {
            /* load source data */
            rc = plg2->load_cb(ly_mod, SR_DS_STARTUP, &mod_data);

            if (!rc) {
                /* write data to target */
                rc = plg1->store_cb(ly_mod, SR_DS_RUNNING, mod_data);
                lyd_free_siblings(mod_data);
            }
        }

        if (rc) {
            sr_errinfo_new(&err_info, rc, "Copying module \"%s\" data from <startup> to <running> failed.",
                    ((char *)main_shm) + shm_mod->name);
            return err_info;
        }
    }

    SR_LOG_INF("Datastore copied from <startup> to <running>.");
    return NULL;
}

/**
 * @brief Fill main SHM dependency information based on internal sysrepo data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] sr_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Main SHM dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] shm_end Current SHM end.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_fill_deps(sr_main_shm_t *main_shm, struct lyd_node *sr_dep_parent, sr_dep_t *shm_deps, size_t *dep_i,
        char **shm_end)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *ref_shm_mod = NULL;
    struct lyd_node *sr_dep, *sr_instid;
    int dep_found;

    assert(!*dep_i);

    LY_LIST_FOR(lyd_child(sr_dep_parent), sr_dep) {
        dep_found = 0;

        if (!strcmp(sr_dep->schema->name, "module")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_REF;

            /* copy module name offset */
            ref_shm_mod = sr_shmmain_find_module(main_shm, lyd_get_value(sr_dep));
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_deps[*dep_i].module = ref_shm_mod->name;

            /* no path */
            shm_deps[*dep_i].path = 0;
        } else if (!strcmp(sr_dep->schema->name, "inst-id")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_INSTID;

            /* there may be no default value */
            shm_deps[*dep_i].module = 0;

            LY_LIST_FOR(lyd_child(sr_dep), sr_instid) {
                if (!strcmp(sr_instid->schema->name, "path")) {
                    /* copy path */
                    shm_deps[*dep_i].path = sr_shmstrcpy((char *)main_shm, lyd_get_value(sr_instid), shm_end);
                } else if (!strcmp(sr_instid->schema->name, "default-module")) {
                    /* copy module name offset */
                    ref_shm_mod = sr_shmmain_find_module(main_shm, lyd_get_value(sr_instid));
                    SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                    shm_deps[*dep_i].module = ref_shm_mod->name;
                }
            }
        }

        assert(!dep_found || shm_deps[*dep_i].module || shm_deps[*dep_i].path);
        if (dep_found) {
            ++(*dep_i);
        }
    }

    return NULL;
}

/**
 * @brief Fill a new SHM module and add its name and enabled features into main SHM. Does not add data/op/inverse dependencies.
 *
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_idx Main SHM mod index to fill.
 * @param[in] shm_main Main SHM structure to remap and add name/features at its end.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_fill_module(const struct lyd_node *sr_mod, size_t shm_mod_idx, sr_shm_t *shm_main)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    struct lyd_node *sr_child;
    off_t *shm_features;
    const char *name;
    char *shm_end;
    size_t feat_i, ds_plugin_i, feat_names_len, ds_plugin_names_len, old_shm_size;
    int ds;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    /* init SHM module structure */
    memset(shm_mod, 0, sizeof *shm_mod);
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[ds].data_lock, 1))) {
            return err_info;
        }
        if ((err_info = sr_mutex_init(&shm_mod->data_lock_info[ds].ds_lock, 1))) {
            return err_info;
        }
    }
    if ((err_info = sr_rwlock_init(&shm_mod->replay_lock, 1))) {
        return err_info;
    }
    shm_mod->ver = 1;
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_rwlock_init(&shm_mod->change_sub[ds].lock, 1))) {
            return err_info;
        }
    }
    if ((err_info = sr_rwlock_init(&shm_mod->oper_lock, 1))) {
        return err_info;
    }
    if ((err_info = sr_rwlock_init(&shm_mod->notif_lock, 1))) {
        return err_info;
    }

    /* remember name, set fields from sr_mod, and count enabled features */
    name = NULL;
    feat_names_len = 0;
    ds_plugin_names_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "name")) {
            /* rememeber name */
            name = lyd_get_value(sr_child);
        } else if (!strcmp(sr_child->schema->name, "revision")) {
            /* copy revision */
            strcpy(shm_mod->rev, lyd_get_value(sr_child));
        } else if (!strcmp(sr_child->schema->name, "replay-support")) {
            /* set replay-support flag */
            ATOMIC_STORE_RELAXED(shm_mod->replay_supp, 1);
        } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* count features and ther names length */
            ++shm_mod->feat_count;
            feat_names_len += sr_strshmlen(lyd_get_value(sr_child));
        } else if (!strcmp(sr_child->schema->name, "plugin")) {
            /* count the length of all datastore plugin names */
            ds_plugin_names_len += sr_strshmlen(lyd_get_value(lyd_child(sr_child)->next));
        }
    }
    assert(name);

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + sr_strshmlen(name) +
            SR_SHM_SIZE(shm_mod->feat_count * sizeof(off_t)) + feat_names_len + ds_plugin_names_len))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;

    /* store module name */
    shm_mod->name = sr_shmstrcpy(shm_main->addr, name, &shm_end);

    /* store feature array */
    shm_mod->features = sr_shmcpy(shm_main->addr, NULL, shm_mod->feat_count * sizeof(off_t), &shm_end);

    /* store feature and datastore plugin names */
    shm_features = (off_t *)(shm_main->addr + shm_mod->features);
    feat_i = 0;
    ds_plugin_i = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* copy feature name */
            shm_features[feat_i] = sr_shmstrcpy(shm_main->addr, lyd_get_value(sr_child), &shm_end);

            ++feat_i;
        } else if (!strcmp(sr_child->schema->name, "plugin")) {
            /* get DS */
            ds = sr_str2mod_ds(lyd_get_value(lyd_child(sr_child)));

            /* copy DS plugin name */
            shm_mod->plugins[ds] = sr_shmstrcpy(shm_main->addr, lyd_get_value(lyd_child(sr_child)->next), &shm_end);

            ++ds_plugin_i;
        }
    }
    SR_CHECK_INT_RET(feat_i != shm_mod->feat_count, err_info);
    SR_CHECK_INT_RET(ds_plugin_i != SR_MOD_DS_PLUGIN_COUNT, err_info);

    /* main SHM size must be exactly what we allocated */
    assert(shm_end == shm_main->addr + shm_main->size);
    return NULL;
}

/**
 * @brief Add module (data and inverse) dependencies into main SHM.
 *
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_idx Main SHM mod index of @p sr_mod.
 * @param[in] shm_main Main SHM structure to remap and append the data to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_add_module_deps(const struct lyd_node *sr_mod, size_t shm_mod_idx, sr_shm_t *shm_main)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_instid;
    sr_mod_t *shm_mod, *ref_shm_mod;
    sr_dep_t *shm_deps;
    off_t *shm_inv_deps;
    sr_main_shm_t *main_shm;
    char *shm_end;
    size_t paths_len, dep_i, inv_dep_i, old_shm_size;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    assert(!shm_mod->dep_count);
    assert(!shm_mod->inv_dep_count);

    /* count arrays and paths length */
    paths_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "deps")) {
            LY_LIST_FOR(lyd_child(sr_child), sr_dep) {
                /* another data dependency */
                ++shm_mod->dep_count;

                /* module name was already counted and type is an enum */
                if (!strcmp(sr_dep->schema->name, "inst-id")) {
                    LY_LIST_FOR(lyd_child(sr_dep), sr_instid) {
                        if (!strcmp(sr_instid->schema->name, "path")) {
                            /* a string */
                            paths_len += sr_strshmlen(lyd_get_value(sr_instid));
                        }
                    }
                }
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-deps")) {
            /* another inverse data dependency */
            ++shm_mod->inv_dep_count;
        }
    }

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + paths_len + SR_SHM_SIZE(shm_mod->dep_count * sizeof(sr_dep_t)) +
            SR_SHM_SIZE(shm_mod->inv_dep_count * sizeof(off_t))))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;
    main_shm = (sr_main_shm_t *)shm_main->addr;

    /* allocate dependencies */
    shm_mod->deps = sr_shmcpy(shm_main->addr, NULL, shm_mod->dep_count * sizeof(sr_dep_t), &shm_end);
    shm_deps = (sr_dep_t *)(shm_main->addr + shm_mod->deps);
    dep_i = 0;

    shm_mod->inv_deps = sr_shmcpy(shm_main->addr, NULL, shm_mod->inv_dep_count * sizeof(off_t), &shm_end);
    shm_inv_deps = (off_t *)(shm_main->addr + shm_mod->inv_deps);
    inv_dep_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "deps")) {
            /* now fill the dependency array */
            if ((err_info = sr_shmmain_fill_deps(main_shm, sr_child, shm_deps, &dep_i, &shm_end))) {
                return err_info;
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-deps")) {
            /* now fill module references */
            ref_shm_mod = sr_shmmain_find_module(main_shm, lyd_get_value(sr_child));
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_inv_deps[inv_dep_i] = ref_shm_mod->name;

            ++inv_dep_i;
        }
    }
    SR_CHECK_INT_RET(dep_i != shm_mod->dep_count, err_info);
    SR_CHECK_INT_RET(inv_dep_i != shm_mod->inv_dep_count, err_info);

    /* main SHM size must be exactly what we allocated */
    assert(shm_end == shm_main->addr + shm_main->size);
    return NULL;
}

/**
 * @brief Add module RPCs/actions with dependencies into main SHM.
 *
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_idx Main SHM mod index of @p sr_mod.
 * @param[in] shm_main Main SHM structure to remap and append the data to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_add_module_rpcs(const struct lyd_node *sr_mod, size_t shm_mod_idx, sr_shm_t *shm_main)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_op, *sr_op_dep, *sr_instid;
    sr_mod_t *shm_mod;
    sr_dep_t *shm_deps;
    sr_rpc_t *shm_rpcs;
    sr_main_shm_t *main_shm;
    char *shm_end;
    size_t paths_len, in_out_deps_len, dep_i, rpc_i, old_shm_size;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    assert(!shm_mod->rpc_count);

    /* count arrays and paths length */
    paths_len = 0;
    in_out_deps_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "rpc")) {
            /* another RPC/action */
            ++shm_mod->rpc_count;

            LY_LIST_FOR(lyd_child(sr_child), sr_op_dep) {
                if (!strcmp(sr_op_dep->schema->name, "path")) {
                    /* operation path (a string) */
                    paths_len += sr_strshmlen(lyd_get_value(sr_op_dep));
                } else if (!strcmp(sr_op_dep->schema->name, "in") || !strcmp(sr_op_dep->schema->name, "out")) {
                    dep_i = 0;
                    LY_LIST_FOR(lyd_child(sr_op_dep), sr_dep) {
                        /* another dependency */
                        ++dep_i;

                        if (!strcmp(sr_dep->schema->name, "inst-id")) {
                            LY_LIST_FOR(lyd_child(sr_dep), sr_instid) {
                                if (!strcmp(sr_instid->schema->name, "path")) {
                                    /* a string */
                                    paths_len += sr_strshmlen(lyd_get_value(sr_instid));
                                }
                            }
                        }
                    }

                    /* all RPC input/output dependencies (must be counted this way to align all the arrays individually) */
                    in_out_deps_len += SR_SHM_SIZE(dep_i * sizeof(sr_dep_t));
                }
            }
        }
    }

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + paths_len + SR_SHM_SIZE(shm_mod->rpc_count * sizeof(sr_rpc_t)) +
            in_out_deps_len))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;
    main_shm = (sr_main_shm_t *)shm_main->addr;

    /* allocate RPCs */
    shm_mod->rpcs = sr_shmcpy(shm_main->addr, NULL, shm_mod->rpc_count * sizeof(sr_rpc_t), &shm_end);
    shm_rpcs = (sr_rpc_t *)(shm_main->addr + shm_mod->rpcs);
    rpc_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "rpc")) {
            /* init lock */
            if ((err_info = sr_rwlock_init(&shm_rpcs[rpc_i].lock, 1))) {
                return err_info;
            }

            LY_LIST_FOR(lyd_child(sr_child), sr_op) {
                if (!strcmp(sr_op->schema->name, "path")) {
                    /* copy xpath name */
                    shm_rpcs[rpc_i].path = sr_shmstrcpy(shm_main->addr, lyd_get_value(sr_op), &shm_end);
                } else if (!strcmp(sr_op->schema->name, "in")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count input deps first */
                        ++shm_rpcs[rpc_i].in_dep_count;
                    }

                    /* allocate array */
                    shm_rpcs[rpc_i].in_deps = sr_shmcpy(shm_main->addr, NULL,
                            shm_rpcs[rpc_i].in_dep_count * sizeof(sr_dep_t), &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_main->addr + shm_rpcs[rpc_i].in_deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmain_fill_deps(main_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_rpcs[rpc_i].in_dep_count, err_info);
                } else if (!strcmp(sr_op->schema->name, "out")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count op output data deps first */
                        ++shm_rpcs[rpc_i].out_dep_count;
                    }

                    /* allocate array */
                    shm_rpcs[rpc_i].out_deps = sr_shmcpy(shm_main->addr, NULL,
                            shm_rpcs[rpc_i].out_dep_count * sizeof(sr_dep_t), &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_main->addr + shm_rpcs[rpc_i].out_deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmain_fill_deps(main_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_rpcs[rpc_i].out_dep_count, err_info);
                }
            }

            ++rpc_i;
        }
    }
    SR_CHECK_INT_RET(rpc_i != shm_mod->rpc_count, err_info);

    /* main SHM size must be exactly what we allocated */
    assert(shm_end == shm_main->addr + shm_main->size);
    return NULL;
}

/**
 * @brief Add module notifications with dependencies into main SHM.
 *
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_idx Main SHM mod index of @p sr_mod.
 * @param[in] shm_main Main SHM structure to remap and append the data to.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_add_module_notifs(const struct lyd_node *sr_mod, size_t shm_mod_idx, sr_shm_t *shm_main)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_op, *sr_op_dep, *sr_instid;
    sr_mod_t *shm_mod;
    sr_dep_t *shm_deps;
    sr_notif_t *shm_notifs;
    sr_main_shm_t *main_shm;
    char *shm_end;
    size_t paths_len, deps_len, dep_i, notif_i, old_shm_size;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    assert(!shm_mod->notif_count);

    /* count arrays and paths length */
    paths_len = 0;
    deps_len = 0;
    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "notification")) {
            /* another notification */
            ++shm_mod->notif_count;

            LY_LIST_FOR(lyd_child(sr_child), sr_op_dep) {
                if (!strcmp(sr_op_dep->schema->name, "path")) {
                    /* operation path (a string) */
                    paths_len += sr_strshmlen(lyd_get_value(sr_op_dep));
                } else if (!strcmp(sr_op_dep->schema->name, "deps")) {
                    dep_i = 0;
                    LY_LIST_FOR(lyd_child(sr_op_dep), sr_dep) {
                        /* another dependency */
                        ++dep_i;

                        if (!strcmp(sr_dep->schema->name, "inst-id")) {
                            LY_LIST_FOR(lyd_child(sr_dep), sr_instid) {
                                if (!strcmp(sr_instid->schema->name, "path")) {
                                    /* a string */
                                    paths_len += sr_strshmlen(lyd_get_value(sr_instid));
                                }
                            }
                        }
                    }

                    /* all notification dependencies (must be counted this way to align all the arrays individually) */
                    deps_len += SR_SHM_SIZE(dep_i * sizeof(sr_dep_t));
                }
            }
        }
    }

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + paths_len + SR_SHM_SIZE(shm_mod->notif_count * sizeof(sr_notif_t)) +
            deps_len))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;
    main_shm = (sr_main_shm_t *)shm_main->addr;

    /* allocate notifications */
    shm_mod->notifs = sr_shmcpy(shm_main->addr, NULL, shm_mod->notif_count * sizeof(sr_notif_t), &shm_end);
    shm_notifs = (sr_notif_t *)(shm_main->addr + shm_mod->notifs);
    notif_i = 0;

    LY_LIST_FOR(lyd_child(sr_mod), sr_child) {
        if (!strcmp(sr_child->schema->name, "notification")) {
            LY_LIST_FOR(lyd_child(sr_child), sr_op) {
                if (!strcmp(sr_op->schema->name, "path")) {
                    /* copy xpath name */
                    shm_notifs[notif_i].path = sr_shmstrcpy(shm_main->addr, lyd_get_value(sr_op), &shm_end);
                } else if (!strcmp(sr_op->schema->name, "deps")) {
                    LY_LIST_FOR(lyd_child(sr_op), sr_op_dep) {
                        /* count deps first */
                        ++shm_notifs[notif_i].dep_count;
                    }

                    /* allocate array */
                    shm_notifs[notif_i].deps = sr_shmcpy(shm_main->addr, NULL,
                            shm_notifs[notif_i].dep_count * sizeof(sr_dep_t), &shm_end);

                    /* fill the array */
                    shm_deps = (sr_dep_t *)(shm_main->addr + shm_notifs[notif_i].deps);
                    dep_i = 0;
                    if ((err_info = sr_shmmain_fill_deps(main_shm, sr_op, shm_deps, &dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(dep_i != shm_notifs[notif_i].dep_count, err_info);
                }
            }

            ++notif_i;
        }
    }
    SR_CHECK_INT_RET(notif_i != shm_mod->notif_count, err_info);

    /* main SHM size must be exactly what we allocated */
    assert(shm_end == shm_main->addr + shm_main->size);
    return NULL;
}

sr_error_info_t *
sr_shmmain_store_modules(sr_conn_ctx_t *conn, struct lyd_node *first_sr_mod)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_mod;
    sr_mod_t *shm_mod;
    uint32_t i, mod_count;

    /* count how many modules are we going to store */
    mod_count = 0;
    LY_LIST_FOR(first_sr_mod, sr_mod) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            ++mod_count;
        }
    }

    /* enlarge main SHM for all the modules */
    if ((err_info = sr_shm_remap(&conn->main_shm, sizeof(sr_main_shm_t) + mod_count * sizeof *shm_mod))) {
        return err_info;
    }

    /* set module count */
    SR_CONN_MAIN_SHM(conn)->mod_count = mod_count;

    /* add all modules into SHM */
    i = 0;
    sr_mod = first_sr_mod;
    while (i < mod_count) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            if ((err_info = sr_shmmain_fill_module(sr_mod, i, &conn->main_shm))) {
                return err_info;
            }

            ++i;
        }

        sr_mod = sr_mod->next;
    }

    /*
     * Dependencies of old modules are rebuild because of possible
     * 1) new inverse dependencies when new modules depend on the old ones;
     * 2) new dependencies in the old modules in case they were added by foreign augments in the new modules.
     * Checking these cases would probably be more costly than just always rebuilding all dependencies.
     */

    /* add all dependencies/operations with dependencies for all modules in SHM, in separate loop because
     * all modules must have their name set so that it can be referenced */
    i = 0;
    sr_mod = first_sr_mod;
    while (i < mod_count) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            if ((err_info = sr_shmmain_add_module_deps(sr_mod, i, &conn->main_shm))) {
                return err_info;
            }
            if ((err_info = sr_shmmain_add_module_rpcs(sr_mod, i, &conn->main_shm))) {
                return err_info;
            }
            if ((err_info = sr_shmmain_add_module_notifs(sr_mod, i, &conn->main_shm))) {
                return err_info;
            }

            ++i;
        }

        sr_mod = sr_mod->next;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_main_open(sr_shm_t *shm, int *created)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    char *shm_name = NULL;
    int creat = 0;

    err_info = sr_path_main_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    /* try to open the shared memory */
    shm->fd = sr_open(shm_name, O_RDWR, SR_MAIN_SHM_PERM);
    if ((shm->fd == -1) && (errno == ENOENT)) {
        if (!created) {
            /* we do not want to create the memory now */
            free(shm_name);
            return NULL;
        }

        /* create shared memory */
        shm->fd = sr_open(shm_name, O_RDWR | O_CREAT | O_EXCL, SR_MAIN_SHM_PERM);
        creat = 1;
    }
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open main shared memory (%s).", strerror(errno));
        goto error;
    }

    /* map it with proper size */
    if ((err_info = sr_shm_remap(shm, creat ? sizeof *main_shm : 0))) {
        goto error;
    }

    main_shm = (sr_main_shm_t *)shm->addr;
    if (creat) {
        /* init the memory */
        main_shm->shm_ver = SR_SHM_VER;
        if ((err_info = sr_mutex_init(&main_shm->lydmods_lock, 1))) {
            goto error;
        }
        if ((err_info = sr_mutex_init(&main_shm->ext_lock, 1))) {
            goto error;
        }
        ATOMIC_STORE_RELAXED(main_shm->new_sr_cid, 1);
        ATOMIC_STORE_RELAXED(main_shm->new_sr_sid, 1);
        ATOMIC_STORE_RELAXED(main_shm->new_sub_id, 1);
        ATOMIC_STORE_RELAXED(main_shm->new_evpipe_num, 1);

        /* remove leftover event pipes */
        sr_remove_evpipes();
    } else {
        /* check versions  */
        if (main_shm->shm_ver != SR_SHM_VER) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Shared memory version mismatch (%" PRIu32 ", expected %d),"
                    " remove the SHM to fix.", main_shm->shm_ver, SR_SHM_VER);
            goto error;
        }
    }

    if (created) {
        *created = creat;
    }
    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_error_info_t *
sr_shmmain_ext_open(sr_shm_t *shm, int zero)
{
    sr_error_info_t *err_info = NULL;
    char *shm_name = NULL;

    err_info = sr_path_ext_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    shm->fd = sr_open(shm_name, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open ext shared memory (%s).", strerror(errno));
        goto error;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? SR_SHM_SIZE(sizeof(sr_ext_shm_t)) : 0))) {
        goto error;
    }
    if (zero) {
        ((sr_ext_shm_t *)shm->addr)->first_hole_off = 0;
    }

    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_mod_t *
sr_shmmain_find_module(sr_main_shm_t *main_shm, const char *name)
{
    sr_mod_t *shm_mod;
    uint32_t i;

    assert(name);

    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        if (!strcmp(((char *)main_shm) + shm_mod->name, name)) {
            return shm_mod;
        }
    }

    return NULL;
}

sr_rpc_t *
sr_shmmain_find_rpc(sr_main_shm_t *main_shm, const char *path)
{
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    char *mod_name;
    uint16_t i;

    assert(path);

    /* find module first */
    mod_name = sr_get_first_ns(path);
    shm_mod = sr_shmmain_find_module(main_shm, mod_name);
    free(mod_name);
    if (!shm_mod) {
        return NULL;
    }

    shm_rpc = (sr_rpc_t *)(((char *)main_shm) + shm_mod->rpcs);
    for (i = 0; i < shm_mod->rpc_count; ++i) {
        if (!strcmp(((char *)main_shm) + shm_rpc[i].path, path)) {
            return &shm_rpc[i];
        }
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_update_replay_support(sr_main_shm_t *main_shm, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    uint32_t i;

    if (mod_name) {
        shm_mod = sr_shmmain_find_module(main_shm, mod_name);
        SR_CHECK_INT_RET(!shm_mod, err_info);

        /* update flag */
        ATOMIC_STORE_RELAXED(shm_mod->replay_supp, replay_support);
    } else {
        for (i = 0; i < main_shm->mod_count; ++i) {
            shm_mod = SR_SHM_MOD_IDX(main_shm, i);

            /* update flag */
            ATOMIC_STORE_RELAXED(shm_mod->replay_supp, replay_support);
        }
    }

    return NULL;
}
