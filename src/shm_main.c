/**
 * @file shm_main.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief main SHM routines
 *
 * @copyright
 * Copyright 2018 Deutsche Telekom AG.
 * Copyright 2018 - 2019 CESNET, z.s.p.o.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "common.h"

#include <assert.h>
#include <ctype.h>
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

    /* startup data dir */
    if ((err_info = sr_path_startup_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* notif dir */
    if ((err_info = sr_path_notif_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
        return err_info;
    }
    if (ret && (err_info = sr_mkpath(dir_path, SR_DIR_PERM))) {
        free(dir_path);
        return err_info;
    }
    free(dir_path);

    /* YANG module dir */
    if ((err_info = sr_path_yang_dir(&dir_path))) {
        return err_info;
    }
    if (((ret = access(dir_path, F_OK)) == -1) && (errno != ENOENT)) {
        free(dir_path);
        SR_ERRINFO_SYSERRNO(&err_info, "access");
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
    mode_t um;

    if (asprintf(&path, "%s/%s", sr_get_repo_path(), SR_MAIN_SHM_LOCK) == -1) {
        SR_ERRINFO_MEM(&err_info);
        return err_info;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    *shm_lock = SR_OPEN(path, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);
    free(path);
    umask(um);
    if (*shm_lock == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "open");
        return err_info;
    }

    return NULL;
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

    /* If the connection is owned by this process a check using flock which
     * requires an open/close would release the lock. Check if the CID is a
     * connection owned by this process and return status before we do an
     * open().
     */
    if (conn_list.head) {
        /* CONN LIST LOCK */
        if ((err_info = sr_mlock(&conn_list.lock, 1000, __func__))) {
            goto cleanup;
        }
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

        /* CONN LIST UNLOCK */
        sr_munlock(&conn_list.lock);
    }

    /* open the file to test the lock */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        goto cleanup;
    }
    fd = open(path, O_RDWR);
    if (fd == -1) {
        /* the file does not exist in which case there is no connection established */
        if (errno == ENOENT) {
            *conn_alive = 0;
            if (pid) {
                *pid = 0;
            }
            goto cleanup;
        }
        SR_ERRINFO_SYSERRNO(&err_info, "open");
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
    mode_t um;
    char buf[64];

    /* open the connection lock file with the correct permissions */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        return err_info;
    }
    um = umask(SR_UMASK);
    fd = SR_OPEN(path, O_CREAT | O_RDWR, SR_INT_FILE_PERM);
    umask(um);
    if (fd == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "open");
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
    if ((err_info = sr_mlock(&conn_list.lock, 1000, __func__))) {
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
    if ((err_info = sr_mlock(&conn_list.lock, 1000, __func__))) {
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
    if (!lys_parse_mem(*ly_ctx, sysrepo_yang, LYS_YANG)) {
        sr_errinfo_new_ly(&err_info, *ly_ctx);
        ly_ctx_destroy(*ly_ctx, NULL);
        *ly_ctx = NULL;
        return err_info;
    }

    return NULL;
}

sr_error_info_t *
sr_shmmain_files_startup2running(sr_main_shm_t *main_shm, int replace)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod = NULL;
    char *startup_path, *running_path;
    const char *mod_name;
    uint32_t i;

    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        mod_name = ((char *)main_shm) + shm_mod->name;

        if ((err_info = sr_path_ds_shm(mod_name, SR_DS_RUNNING, &running_path))) {
            goto error;
        }

        if (!replace && sr_file_exists(running_path)) {
            /* there are some running data, keep them */
            free(running_path);
            continue;
        }

        if ((err_info = sr_path_startup_file(mod_name, &startup_path))) {
            free(running_path);
            goto error;
        }
        err_info = sr_cp_file2shm(running_path, startup_path, SR_FILE_PERM);
        free(startup_path);
        free(running_path);
        if (err_info) {
            goto error;
        }
    }

    if (replace) {
        SR_LOG_INF("Datastore copied from <startup> to <running>.");
    }
    return NULL;

error:
    sr_errinfo_new(&err_info, SR_ERR_INTERNAL, NULL, "Copying module \"%s\" data from <startup> to <running> failed.", mod_name);
    return err_info;
}

/**
 * @brief Fill main SHM data dependency information based on internal sysrepo data.
 *
 * @param[in] main_shm Main SHM.
 * @param[in] sr_dep_parent Dependencies in internal sysrepo data.
 * @param[in] shm_deps Main SHM data dependencies to fill.
 * @param[out] dep_i Number of dependencies filled.
 * @param[in,out] shm_end Current SHM end.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_fill_data_deps(sr_main_shm_t *main_shm, struct lyd_node *sr_dep_parent, sr_mod_data_dep_t *shm_deps,
        size_t *dep_i, char **shm_end)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *ref_shm_mod = NULL;
    struct lyd_node *sr_dep, *sr_instid;
    const char *str;
    int dep_found;

    assert(!*dep_i);

    LY_TREE_FOR(sr_dep_parent->child, sr_dep) {
        dep_found = 0;

        if (!strcmp(sr_dep->schema->name, "module")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_REF;

            /* copy module name offset */
            str = sr_ly_leaf_value_str(sr_dep);
            ref_shm_mod = sr_shmmain_find_module(main_shm, str, 0);
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_deps[*dep_i].module = ref_shm_mod->name;

            /* no xpath */
            shm_deps[*dep_i].xpath = 0;
        } else if (!strcmp(sr_dep->schema->name, "inst-id")) {
            dep_found = 1;

            /* set dep type */
            shm_deps[*dep_i].type = SR_DEP_INSTID;

            /* there may be no default value */
            shm_deps[*dep_i].module = 0;

            LY_TREE_FOR(sr_dep->child, sr_instid) {
                if (!strcmp(sr_instid->schema->name, "xpath")) {
                    /* copy xpath */
                    str = sr_ly_leaf_value_str(sr_instid);
                    shm_deps[*dep_i].xpath = sr_shmstrcpy((char *)main_shm, str, shm_end);
                } else if (!strcmp(sr_instid->schema->name, "default-module")) {
                    /* copy module name offset */
                    str = sr_ly_leaf_value_str(sr_instid);
                    ref_shm_mod = sr_shmmain_find_module(main_shm, str, 0);
                    SR_CHECK_INT_RET(!ref_shm_mod, err_info);
                    shm_deps[*dep_i].module = ref_shm_mod->name;
                }
            }
        }

        assert(!dep_found || shm_deps[*dep_i].module || shm_deps[*dep_i].xpath);
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
    const char *name, *str;
    char *shm_end;
    size_t feat_i, feat_names_len, old_shm_size;
    sr_datastore_t ds;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    /* init SHM module structure */
    memset(shm_mod, 0, sizeof *shm_mod);
    for (ds = 0; ds < SR_DS_COUNT; ++ds) {
        if ((err_info = sr_rwlock_init(&shm_mod->data_lock_info[ds].lock, 1))) {
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
    LY_TREE_FOR(sr_mod->child, sr_child) {
        if (!strcmp(sr_child->schema->name, "name")) {
            /* rememeber name */
            name = sr_ly_leaf_value_str(sr_child);
        } else if (!strcmp(sr_child->schema->name, "revision")) {
            /* copy revision */
            str = sr_ly_leaf_value_str(sr_child);
            strcpy(shm_mod->rev, str);
        } else if (!strcmp(sr_child->schema->name, "replay-support")) {
            /* set replay-support flag */
            ATOMIC_STORE_RELAXED(shm_mod->replay_supp, 1);
        } else if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* count features and ther names length */
            ++shm_mod->feat_count;
            str = sr_ly_leaf_value_str(sr_child);
            feat_names_len += sr_strshmlen(str);
        }
    }
    assert(name);

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + sr_strshmlen(name) +
            SR_SHM_SIZE(shm_mod->feat_count * sizeof(off_t)) + feat_names_len))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;

    /* store module name */
    shm_mod->name = sr_shmstrcpy(shm_main->addr, name, &shm_end);

    /* store feature array */
    shm_mod->features = sr_shmcpy(shm_main->addr, NULL, shm_mod->feat_count * sizeof(off_t), &shm_end);

    /* store feature names */
    shm_features = (off_t *)(shm_main->addr + shm_mod->features);
    feat_i = 0;
    LY_TREE_FOR(sr_mod->child, sr_child) {
        if (!strcmp(sr_child->schema->name, "enabled-feature")) {
            /* copy feature name */
            str = sr_ly_leaf_value_str(sr_child);
            shm_features[feat_i] = sr_shmstrcpy(shm_main->addr, str, &shm_end);

            ++feat_i;
        }
    }
    SR_CHECK_INT_RET(feat_i != shm_mod->feat_count, err_info);

    /* main SHM size must be exactly what we allocated */
    assert(shm_end == shm_main->addr + shm_main->size);
    return NULL;
}

/**
 * @brief Add module data/op/inverse dependencies into main SHM.
 *
 * @param[in] sr_mod Module to read the information from.
 * @param[in] shm_mod_idx Main SHM mod index of @p sr_mod.
 * @param[in] shm_main Main SHM structure to remap and add all the deps at its end.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmmain_add_module_deps(const struct lyd_node *sr_mod, size_t shm_mod_idx, sr_shm_t *shm_main)
{
    sr_error_info_t *err_info = NULL;
    struct lyd_node *sr_child, *sr_dep, *sr_op, *sr_op_dep, *sr_instid;
    sr_mod_t *shm_mod, *ref_shm_mod;
    sr_mod_data_dep_t *shm_data_deps, *shm_op_data_deps;
    sr_mod_op_dep_t *shm_op_deps;
    off_t *shm_inv_data_deps;
    sr_main_shm_t *main_shm;
    char *shm_end;
    const char *str;
    size_t strings_len, op_data_deps_len, data_dep_i, inv_data_dep_i, op_dep_i, op_data_dep_i, old_shm_size;

    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);

    assert(!shm_mod->data_dep_count);
    assert(!shm_mod->inv_data_dep_count);
    assert(!shm_mod->op_dep_count);

    /* count array and stirng length */
    strings_len = 0;
    op_data_deps_len = 0;
    LY_TREE_FOR(sr_mod->child, sr_child) {
        if (!strcmp(sr_child->schema->name, "data-deps")) {
            LY_TREE_FOR(sr_child->child, sr_dep) {
                /* another data dependency */
                ++shm_mod->data_dep_count;

                /* module name was already counted and type is an enum */
                if (!strcmp(sr_dep->schema->name, "inst-id")) {
                    LY_TREE_FOR(sr_dep->child, sr_instid) {
                        if (!strcmp(sr_instid->schema->name, "xpath")) {
                            /* a string */
                            str = sr_ly_leaf_value_str(sr_instid);
                            strings_len += sr_strshmlen(str);
                        }
                    }
                }
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
            /* another inverse data dependency */
            ++shm_mod->inv_data_dep_count;
        } else if (!strcmp(sr_child->schema->name, "op-deps")) {
            /* another operation dependency */
            ++shm_mod->op_dep_count;

            LY_TREE_FOR(sr_child->child, sr_op_dep) {
                if (!strcmp(sr_op_dep->schema->name, "xpath")) {
                    /* operation xpath (a string) */
                    str = sr_ly_leaf_value_str(sr_op_dep);
                    strings_len += sr_strshmlen(str);
                } else if (!strcmp(sr_op_dep->schema->name, "in") || !strcmp(sr_op_dep->schema->name, "out")) {
                    data_dep_i = 0;
                    LY_TREE_FOR(sr_op_dep->child, sr_dep) {
                        /* another data dependency */
                        ++data_dep_i;

                        if (!strcmp(sr_dep->schema->name, "inst-id")) {
                            LY_TREE_FOR(sr_dep->child, sr_instid) {
                                if (!strcmp(sr_instid->schema->name, "xpath")) {
                                    /* a string */
                                    str = sr_ly_leaf_value_str(sr_instid);
                                    strings_len += sr_strshmlen(str);
                                }
                            }
                        }
                    }

                    /* all operation data dependencies */
                    op_data_deps_len += SR_SHM_SIZE(data_dep_i * sizeof(sr_mod_data_dep_t));
                }
            }
        }
    }

    /* remember main SHM size */
    old_shm_size = shm_main->size;

    /* enlarge and possibly remap main SHM */
    if ((err_info = sr_shm_remap(shm_main, shm_main->size + strings_len +
            SR_SHM_SIZE(shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t)) +
            SR_SHM_SIZE(shm_mod->inv_data_dep_count * sizeof(off_t)) +
            SR_SHM_SIZE(shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t)) + op_data_deps_len))) {
        return err_info;
    }
    shm_mod = SR_SHM_MOD_IDX(shm_main->addr, shm_mod_idx);
    shm_end = shm_main->addr + old_shm_size;
    main_shm = (sr_main_shm_t *)shm_main->addr;

    /* allocate and fill arrays */
    shm_mod->data_deps = sr_shmcpy(shm_main->addr, NULL, shm_mod->data_dep_count * sizeof(sr_mod_data_dep_t), &shm_end);
    shm_data_deps = (sr_mod_data_dep_t *)(shm_main->addr + shm_mod->data_deps);
    data_dep_i = 0;

    shm_mod->inv_data_deps = sr_shmcpy(shm_main->addr, NULL, shm_mod->inv_data_dep_count * sizeof(off_t), &shm_end);
    shm_inv_data_deps = (off_t *)(shm_main->addr + shm_mod->inv_data_deps);
    inv_data_dep_i = 0;

    shm_mod->op_deps = sr_shmcpy(shm_main->addr, NULL, shm_mod->op_dep_count * sizeof(sr_mod_op_dep_t), &shm_end);
    shm_op_deps = (sr_mod_op_dep_t *)(shm_main->addr + shm_mod->op_deps);
    op_dep_i = 0;

    LY_TREE_FOR(sr_mod->child, sr_child) {
        if (!strcmp(sr_child->schema->name, "data-deps")) {
            /* now fill the dependency array */
            if ((err_info = sr_shmmain_fill_data_deps(main_shm, sr_child, shm_data_deps, &data_dep_i, &shm_end))) {
                return err_info;
            }
        } else if (!strcmp(sr_child->schema->name, "inverse-data-deps")) {
            /* now fill module references */
            str = sr_ly_leaf_value_str(sr_child);
            ref_shm_mod = sr_shmmain_find_module(main_shm, str, 0);
            SR_CHECK_INT_RET(!ref_shm_mod, err_info);
            shm_inv_data_deps[inv_data_dep_i] = ref_shm_mod->name;

            ++inv_data_dep_i;
        } else if (!strcmp(sr_child->schema->name, "op-deps")) {
            LY_TREE_FOR(sr_child->child, sr_op) {
                if (!strcmp(sr_op->schema->name, "xpath")) {
                    /* copy xpath name */
                    str = sr_ly_leaf_value_str(sr_op);
                    shm_op_deps[op_dep_i].xpath = sr_shmstrcpy(shm_main->addr, str, &shm_end);
                } else if (!strcmp(sr_op->schema->name, "in")) {
                    LY_TREE_FOR(sr_op->child, sr_op_dep) {
                        /* count op input data deps first */
                        ++shm_op_deps[op_dep_i].in_dep_count;
                    }

                    /* allocate array */
                    shm_op_deps[op_dep_i].in_deps = sr_shmcpy(shm_main->addr, NULL,
                            shm_op_deps[op_dep_i].in_dep_count * sizeof(sr_mod_data_dep_t), &shm_end);

                    /* fill the array */
                    shm_op_data_deps = (sr_mod_data_dep_t *)(shm_main->addr + shm_op_deps[op_dep_i].in_deps);
                    op_data_dep_i = 0;
                    if ((err_info = sr_shmmain_fill_data_deps(main_shm, sr_op, shm_op_data_deps, &op_data_dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].in_dep_count, err_info);
                } else if (!strcmp(sr_op->schema->name, "out")) {
                    LY_TREE_FOR(sr_op->child, sr_op_dep) {
                        /* count op output data deps first */
                        ++shm_op_deps[op_dep_i].out_dep_count;
                    }

                    /* allocate array */
                    shm_op_deps[op_dep_i].out_deps = sr_shmcpy(shm_main->addr, NULL,
                            shm_op_deps[op_dep_i].out_dep_count * sizeof(sr_mod_data_dep_t), &shm_end);

                    /* fill the array */
                    shm_op_data_deps = (sr_mod_data_dep_t *)(shm_main->addr + shm_op_deps[op_dep_i].out_deps);
                    op_data_dep_i = 0;
                    if ((err_info = sr_shmmain_fill_data_deps(main_shm, sr_op, shm_op_data_deps, &op_data_dep_i, &shm_end))) {
                        return err_info;
                    }
                    SR_CHECK_INT_RET(op_data_dep_i != shm_op_deps[op_dep_i].out_dep_count, err_info);
                }
            }

            ++op_dep_i;
        }
    }
    SR_CHECK_INT_RET(data_dep_i != shm_mod->data_dep_count, err_info);
    SR_CHECK_INT_RET(inv_data_dep_i != shm_mod->inv_data_dep_count, err_info);
    SR_CHECK_INT_RET(op_dep_i != shm_mod->op_dep_count, err_info);

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
    LY_TREE_FOR(first_sr_mod, sr_mod) {
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

    /* add all dependencies for all modules in SHM, in separate loop because all modules must have their name set */
    i = 0;
    sr_mod = first_sr_mod;
    while (i < mod_count) {
        if (!strcmp(sr_mod->schema->name, "module")) {
            if ((err_info = sr_shmmain_add_module_deps(sr_mod, i, &conn->main_shm))) {
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
    mode_t um;

    err_info = sr_path_main_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    /* try to open the shared memory */
    shm->fd = SR_OPEN(shm_name, O_RDWR, SR_MAIN_SHM_PERM);
    if ((shm->fd == -1) && (errno == ENOENT)) {
        if (!created) {
            /* we do not want to create the memory now */
            free(shm_name);
            return NULL;
        }

        /* set umask so that the correct permissions are really set */
        um = umask(SR_UMASK);

        /* create shared memory */
        shm->fd = SR_OPEN(shm_name, O_RDWR | O_CREAT | O_EXCL, SR_MAIN_SHM_PERM);
        umask(um);
        creat = 1;
    }
    free(shm_name);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open shared memory (%s).", strerror(errno));
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
        if ((err_info = sr_rwlock_init(&main_shm->rpc_lock, 1))) {
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
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Shared memory version mismatch (%u, expected %u),"
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
    mode_t um;

    err_info = sr_path_ext_shm(&shm_name);
    if (err_info) {
        return err_info;
    }

    /* set umask so that the correct permissions are really set */
    um = umask(SR_UMASK);

    shm->fd = SR_OPEN(shm_name, O_RDWR | O_CREAT, SR_MAIN_SHM_PERM);
    free(shm_name);
    umask(um);
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, NULL, "Failed to open ext shared memory (%s).", strerror(errno));
        goto error;
    }

    /* either zero the memory or keep it exactly the way it was */
    if ((err_info = sr_shm_remap(shm, zero ? sizeof(sr_ext_shm_t) : 0))) {
        goto error;
    }
    if (zero) {
        ATOMIC_STORE_RELAXED(((sr_ext_shm_t *)shm->addr)->wasted, 0);
    }

    return NULL;

error:
    sr_shm_clear(shm);
    return err_info;
}

sr_mod_t *
sr_shmmain_find_module(sr_main_shm_t *main_shm, const char *name, off_t name_off)
{
    uint32_t i;
    sr_mod_t *shm_mod;

    assert(name || name_off);

    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        if (name_off && (shm_mod->name == name_off)) {
            return shm_mod;
        } else if (name && !strcmp(((char *)main_shm) + shm_mod->name, name)) {
            return shm_mod;
        }
    }

    return NULL;
}

sr_rpc_t *
sr_shmmain_find_rpc(sr_main_shm_t *main_shm, char *ext_shm_addr, const char *op_path, off_t op_path_off)
{
    sr_rpc_t *shm_rpc;
    uint16_t i;

    assert(op_path || op_path_off);

    shm_rpc = (sr_rpc_t *)(ext_shm_addr + main_shm->rpcs);
    for (i = 0; i < main_shm->rpc_count; ++i) {
        if (op_path_off && (shm_rpc[i].op_path == op_path_off)) {
            return &shm_rpc[i];
        } else if (op_path && !strcmp(ext_shm_addr + shm_rpc[i].op_path, op_path)) {
            return &shm_rpc[i];
        }
    }

    return NULL;
}

/**
 * @brief Perform full recovery of a dead connection.
 * Main SHM read upgr lock and remap write lock must be held!
 *
 * Includes (is only checked and ignored or in some cases also recovered when accessed):
 * - removing any matching subscriptions and their evpipe files;
 * - removing any stored operational data;
 * - removing connection lock file.
 *
 * Excludes (is recovered when accessed):
 * - recovering main SHM locks;
 * - recovering module locks;
 * - recovering subscription SHMs and locks inside.
 *
 * @param[in] conn Connection to use.
 * @param[in] cid Dead connection ID to recover.
 */
static void
sr_shmmain_conn_recover(sr_conn_ctx_t *conn, sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    sr_datastore_t ds;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    int last_removed;
    uint32_t i;
    char *path;

    SR_LOG_WRN("Performing full recovery of a crashed connection with CID %" PRIu32 ".", cid);

    /* go through all the modules and recover their subscriptions */
    for (i = 0; i < SR_CONN_MAIN_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->main_shm.addr, i);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if ((err_info = sr_shmmod_change_subscription_stop(conn, shm_mod, ds, NULL, 0, 0, 0, cid, 1))) {
                sr_errinfo_free(&err_info);
            }
        }
        if ((err_info = sr_shmmod_oper_subscription_stop(conn, shm_mod, NULL, 0, cid, 1))) {
            sr_errinfo_free(&err_info);
        }
        if ((err_info = sr_shmmod_notif_subscription_stop(conn, shm_mod, 0, 0, cid, 1))) {
            sr_errinfo_free(&err_info);
        }
    }

    /* go through all the RPCs and recover their subscriptions */
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + SR_CONN_MAIN_SHM(conn)->rpcs);
    i = 0;
    while (i < SR_CONN_MAIN_SHM(conn)->rpc_count) {
        if ((err_info = sr_shmmain_rpc_subscription_stop(conn, &shm_rpc[i], NULL, 0, 0, cid, 1, &last_removed))) {
            sr_errinfo_free(&err_info);
        }
        if (!last_removed) {
            ++i;
        }
    }

    /* remove any stored operational data of this connection */
    if ((err_info = sr_shmmod_oper_stored_del_conn(conn, cid))) {
        sr_errinfo_free(&err_info);
    }

    /* remove connection lock file */
    if ((err_info = sr_path_conn_lockfile(cid, &path))) {
        sr_errinfo_free(&err_info);
    } else {
        if (unlink(path) == -1) {
            sr_errinfo_new(&err_info, SR_ERR_SYS, "Removing \"%s\" failed.", path);
            sr_errinfo_free(&err_info);
        }
        free(path);
    }
}

sr_error_info_t *
sr_shmmain_rpc_subscription_add(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off, rpc_off;
    sr_rpc_sub_t *shm_sub;
    uint32_t i;

    assert(xpath);

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SUBS_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* check that this exact subscription does not exist yet */
    shm_sub = (sr_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub->priority == priority) {
            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, NULL, "RPC subscription for \"%s\" with priority %u "
                    "already exists.", conn->ext_shm.addr + shm_rpc->op_path, priority);
            goto cleanup;
        }
    }

    /* add new subscription with its xpath */
    rpc_off = ((char *)shm_rpc) - conn->ext_shm.addr;
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_rpc->subs, &shm_rpc->sub_count, 1, sizeof *shm_sub, -1,
            (void **)&shm_sub, sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup;
    }
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + rpc_off);

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->evpipe_num = evpipe_num;
    shm_sub->cid = conn->cid;

cleanup:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SUBS_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmmain_rpc_subscription_del(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        uint32_t evpipe_num, sr_cid_t cid, int *last_removed, uint32_t *evpipe_num_p, int *found)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_sub_t *shm_sub;
    uint16_t i;

    if (last_removed) {
        *last_removed = 0;
    }

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SUBS_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* find the subscription */
    shm_sub = (sr_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (cid) {
            if (shm_sub[i].cid == cid) {
                break;
            }
        } else if (!strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath) && (shm_sub[i].priority == priority)
                && (shm_sub[i].evpipe_num == evpipe_num)) {
            break;
        }
    }
    if (i == shm_rpc->sub_count) {
        /* no matching subscription found */
        if (found) {
            *found = 0;
        }
        goto cleanup;
    }
    if (found) {
        *found = 1;
    }

    if (evpipe_num_p) {
        *evpipe_num_p = shm_sub[i].evpipe_num;
    }

    /* delete the subscription */
    sr_shmrealloc_del(conn->ext_shm.addr, &shm_rpc->subs, &shm_rpc->sub_count, sizeof *shm_sub, i,
            sr_strshmlen(conn->ext_shm.addr + shm_sub[i].xpath));

    if (last_removed && !shm_rpc->subs) {
        *last_removed = 1;
    }

cleanup:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, SR_SUBS_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmmain_rpc_subscription_stop(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, const char *xpath, uint32_t priority,
        uint32_t evpipe_num, sr_cid_t cid, int del_evpipe, int *last_removed)
{
    sr_error_info_t *err_info = NULL;
    char *mod_name, *path;
    const char *op_path;
    int last_sub_removed, found;
    uint32_t evpipe_num_p;

    if (last_removed) {
        *last_removed = 0;
    }

    op_path = conn->ext_shm.addr + shm_rpc->op_path;

    do {
        /* remove the subscription from the main SHM */
        if ((err_info = sr_shmmain_rpc_subscription_del(conn, shm_rpc, xpath, priority, evpipe_num, cid, &last_sub_removed,
                &evpipe_num_p, &found))) {
            break;
        }
        if (!found) {
            if (!cid) {
                SR_ERRINFO_INT(&err_info);
            }
            break;
        }

        if (del_evpipe) {
            /* delete the evpipe file, it could have been already deleted */
            if ((err_info = sr_path_evpipe(evpipe_num_p, &path))) {
                break;
            }
            unlink(path);
            free(path);
        }

        if (last_sub_removed) {
            /* get module name */
            mod_name = sr_get_first_ns(op_path);

            /* delete the SHM file itself so that there is no leftover event */
            err_info = sr_path_sub_shm(mod_name, "rpc", sr_str_hash(op_path), &path);
            free(mod_name);
            if (err_info) {
                break;
            }
            if (unlink(path) == -1) {
                SR_LOG_WRN("Failed to unlink SHM \"%s\" (%s).", path, strerror(errno));
            }
            free(path);

            /* delete also RPC, we must break because shm_rpc was removed */
            err_info = sr_shmmain_del_rpc(conn, NULL, shm_rpc->op_path);
            if (!err_info && last_removed) {
                *last_removed = 1;
            }
            break;
        }
    } while (cid);

    return err_info;
}

sr_error_info_t *
sr_shmmain_add_rpc(sr_conn_ctx_t *conn, const char *op_path, sr_rpc_t **shm_rpc_p)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    off_t op_path_off;
    sr_rpc_t *shm_rpc;

    main_shm = SR_CONN_MAIN_SHM(conn);
    shm_rpc = (sr_rpc_t *)(conn->ext_shm.addr + main_shm->rpcs);

#ifndef NDEBUG
    uint32_t i;

    /* check that this RPC does not exist yet */
    for (i = 0; i < main_shm->rpc_count; ++i) {
        assert(strcmp(conn->ext_shm.addr + shm_rpc[i].op_path, op_path));
    }
#endif

    /* add new RPC and allocate SHM for op_path */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &main_shm->rpcs, &main_shm->rpc_count, 0, sizeof *shm_rpc, -1,
            (void **)&shm_rpc, sr_strshmlen(op_path), &op_path_off))) {
        return err_info;
    }

    /* fill new RPC */
    strcpy(conn->ext_shm.addr + op_path_off, op_path);
    shm_rpc->op_path = op_path_off;

    if ((err_info = sr_rwlock_init(&shm_rpc->lock, 1))) {
        return err_info;
    }
    shm_rpc->subs = 0;
    shm_rpc->sub_count = 0;

    if (!err_info && shm_rpc_p) {
        *shm_rpc_p = shm_rpc;
    }
    return NULL;
}

sr_error_info_t *
sr_shmmain_del_rpc(sr_conn_ctx_t *conn, const char *op_path, off_t op_path_off)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    sr_rpc_t *shm_rpc;
    uint16_t i;

    main_shm = SR_CONN_MAIN_SHM(conn);

    shm_rpc = sr_shmmain_find_rpc(main_shm, conn->ext_shm.addr, op_path, op_path_off);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* get index instead */
    i = shm_rpc - ((sr_rpc_t *)(conn->ext_shm.addr + main_shm->rpcs));

    /* remove the RPC and its op_path */
    sr_shmrealloc_del(conn->ext_shm.addr, &main_shm->rpcs, &main_shm->rpc_count, sizeof *shm_rpc, i,
            sr_strshmlen(conn->ext_shm.addr + shm_rpc->op_path));

    return NULL;
}

sr_error_info_t *
sr_shmmain_update_replay_support(sr_main_shm_t *main_shm, const char *mod_name, int replay_support)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    uint32_t i;

    if (mod_name) {
        shm_mod = sr_shmmain_find_module(main_shm, mod_name, 0);
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

sr_error_info_t *
sr_shmmain_update_notif_suspend(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int suspend)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_notif_sub_t *shm_sub;
    uint32_t i;

    /* find the subscription in SHM */
    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), mod_name, 0);
    SR_CHECK_INT_RET(!shm_mod, err_info);
    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_RET(i == shm_mod->notif_sub_count, err_info);

    /* check whether the flag can be changed */
    if (suspend && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Notification subscription with ID \"%u\" already suspended.",
                sub_id);
        return err_info;
    } else if (!suspend && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
        sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, NULL, "Notification subscription with ID \"%u\" not suspended.",
                sub_id);
        return err_info;
    }

    /* set the flag */
    ATOMIC_STORE_RELAXED(shm_sub[i].suspended, suspend);

    return NULL;
}

sr_error_info_t *
sr_shmmain_check_data_files(sr_main_shm_t *main_shm)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    const char *mod_name;
    char *owner, *cur_owner, *group, *cur_group, *path;
    mode_t perm, cur_perm;
    int exists;
    uint32_t i;

    for (i = 0; i < main_shm->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, i);
        mod_name = ((char *)main_shm) + shm_mod->name;

        /* this must succeed for every (sysrepo) user */
        if ((err_info = sr_perm_get(mod_name, SR_DS_STARTUP, &owner, &group, &perm))) {
            return err_info;
        }

        /* keep only read/write bits */
        perm &= 00666;

        /*
         * running file, it must exist
         */
        if ((err_info = sr_perm_get(mod_name, SR_DS_RUNNING, &cur_owner, &cur_group, &cur_perm))) {
            goto error;
        }

        /* learn changes */
        if (!strcmp(owner, cur_owner)) {
            free(cur_owner);
            cur_owner = NULL;
        } else {
            free(cur_owner);
            cur_owner = owner;
        }
        if (!strcmp(group, cur_group)) {
            free(cur_group);
            cur_group = NULL;
        } else {
            free(cur_group);
            cur_group = group;
        }
        if (perm == cur_perm) {
            cur_perm = 0;
        } else {
            cur_perm = perm;
        }

        if (cur_owner || cur_group || cur_perm) {
            /* set correct values on the file */
            if ((err_info = sr_path_ds_shm(mod_name, SR_DS_RUNNING, &path))) {
                goto error;
            }
            err_info = sr_chmodown(path, cur_owner, cur_group, cur_perm);
            free(path);
            if (err_info) {
                goto error;
            }
        }

        /*
         * operational file, may not exist
         */
        if ((err_info = sr_path_ds_shm(mod_name, SR_DS_OPERATIONAL, &path))) {
            goto error;
        }
        exists = sr_file_exists(path);
        free(path);
        if (!exists && (err_info = sr_module_file_data_set(mod_name, SR_DS_OPERATIONAL, NULL, O_CREAT | O_EXCL, SR_FILE_PERM))) {
            goto error;
        }

        if ((err_info = sr_perm_get(mod_name, SR_DS_OPERATIONAL, &cur_owner, &cur_group, &cur_perm))) {
            goto error;
        }

        /* learn changes */
        if (!strcmp(owner, cur_owner)) {
            free(cur_owner);
            cur_owner = NULL;
        } else {
            free(cur_owner);
            cur_owner = owner;
        }
        if (!strcmp(group, cur_group)) {
            free(cur_group);
            cur_group = NULL;
        } else {
            free(cur_group);
            cur_group = group;
        }
        if (perm == cur_perm) {
            cur_perm = 0;
        } else {
            cur_perm = perm;
        }

        if (cur_owner || cur_group || cur_perm) {
            /* set correct values on the file */
            if ((err_info = sr_path_ds_shm(mod_name, SR_DS_OPERATIONAL, &path))) {
                goto error;
            }
            err_info = sr_chmodown(path, cur_owner, cur_group, cur_perm);
            free(path);
            if (err_info) {
                goto error;
            }
        }

        free(owner);
        free(group);
    }

    return NULL;

error:
    free(owner);
    free(group);
    return err_info;
}
