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

#include "compat.h"
#include "shm_main.h"

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
#include "config.h"
#include "log.h"
#include "plugins_datastore.h"
#include "sysrepo.h"

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
 * disconnect (eg crash) will have the lock removed automatically as the
 * terminated process is cleaned up.
 */
static struct {
    pthread_mutex_t list_lock;          /**< lock for accessing the connection list */
    struct sr_conn_list_s {
        struct sr_conn_list_s *_next;   /**< pointer to the next connection in the list */
        sr_cid_t cid;                   /**< CID of a connection in this process */
        int lock_fd;                    /**< locked fd of a connection in this process */
    } *list_head;                       /**< process connection list head */

    pthread_mutex_t create_lock;        /**< lock used for synchronizing new connection creation within the process */
} conn_proc = {.list_lock = PTHREAD_MUTEX_INITIALIZER, .list_head = NULL, .create_lock = PTHREAD_MUTEX_INITIALIZER};

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
    if ((err_info = sr_path_conn_lockfile(0, 0, &dir_path))) {
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

    *shm_lock = sr_open(path, O_RDWR | O_CREAT, SR_SHM_PERM);

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

    /* thread sync */

    /* CONN CREATE LOCK */
    if ((err_info = sr_mlock(&conn_proc.create_lock, -1, __func__, NULL, NULL))) {
        return err_info;
    }

    /* process sync */
    memset(&fl, 0, sizeof fl);
    fl.l_type = F_WRLCK;
    do {
        ret = fcntl(shm_lock, F_SETLKW, &fl);
    } while ((ret == -1) && (errno == EINTR));
    if (ret == -1) {
        /* CONN CREATE UNLOCK */
        sr_munlock(&conn_proc.create_lock);

        SR_ERRINFO_SYSERRNO(&err_info, "fcntl");
        return err_info;
    }

    return NULL;
}

void
sr_shmmain_createunlock(int shm_lock)
{
    struct flock fl;

    /* process sync */
    memset(&fl, 0, sizeof fl);
    fl.l_type = F_UNLCK;
    if (fcntl(shm_lock, F_SETLK, &fl) == -1) {
        assert(0);
    }

    /* thread sync */

    /* CONN CREATE UNLOCK */
    sr_munlock(&conn_proc.create_lock);
}

sr_error_info_t *
sr_shmmain_conn_check(sr_cid_t cid, int *conn_alive, pid_t *pid)
{
    sr_error_info_t *err_info = NULL;
    struct flock fl = {0};
    int fd, rc;
    char *path = NULL;
    struct sr_conn_list_s *ptr;

    assert(cid && conn_alive);

    /* CONN LIST LOCK */
    if ((err_info = sr_mlock(&conn_proc.list_lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        goto cleanup;
    }

    /* If the connection is owned by this process a check using flock which
     * requires an open/close would release the lock. Check if the CID is a
     * connection owned by this process and return status before we do an
     * open().
     */
    if (conn_proc.list_head) {
        for (ptr = conn_proc.list_head; ptr; ptr = ptr->_next) {
            if (cid == ptr->cid) {
                /* alive connection of this process */
                *conn_alive = 1;
                if (pid) {
                    *pid = getpid();
                }

                /* CONN LIST UNLOCK */
                sr_munlock(&conn_proc.list_lock);
                goto cleanup;
            }
        }
    }

    /* CONN LIST UNLOCK */
    sr_munlock(&conn_proc.list_lock);

    /* open the file to test the lock */
    if ((err_info = sr_path_conn_lockfile(cid, 0, &path))) {
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
    char *new_path = NULL, *path = NULL;
    int fd = -1;
    struct flock fl = {0};
    char buf[64];

    /* open the new connection lock file with the correct permissions */
    if ((err_info = sr_path_conn_lockfile(cid, 1, &new_path))) {
        return err_info;
    }
    fd = sr_open(new_path, O_CREAT | O_RDWR, SR_CONN_LOCKFILE_PERM);
    if (fd == -1) {
        SR_ERRINFO_SYSERRPATH(&err_info, "open", new_path);
        goto cleanup;
    }

    /* write the PID into the file for debug, the / helps identify if a
     * file is unexpectedly reused. */
    snprintf(buf, sizeof(buf) - 1, "/%ld\n", (long)getpid());
    if (write(fd, buf, strlen(buf)) != (ssize_t)strlen(buf)) {
        SR_ERRINFO_SYSERRNO(&err_info, "write");
        goto cleanup;
    }

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

    /* now that the lock is held, we can rename the file and make it visible */
    if ((err_info = sr_path_conn_lockfile(cid, 0, &path))) {
        goto cleanup;
    }
    if (rename(new_path, path) == -1) {
        SR_ERRINFO_SYSERRNO(&err_info, "rename");
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
    free(new_path);
    free(path);
    return err_info;
}

sr_error_info_t *
sr_shmmain_conn_list_add(sr_cid_t cid)
{
    sr_error_info_t *err_info = NULL;
    struct sr_conn_list_s *conn_item = NULL;
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
    if ((err_info = sr_mlock(&conn_proc.list_lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        goto error;
    }

    /* insert at the head of the list */
    conn_item->_next = conn_proc.list_head;
    conn_proc.list_head = conn_item;

    /* CONN LIST UNLOCK */
    sr_munlock(&conn_proc.list_lock);

    return NULL;

error:
    if (lock_fd > -1) {
        char *path;
        sr_error_info_t *err_info_2 = NULL;

        close(lock_fd);
        if ((err_info_2 = sr_path_conn_lockfile(cid, 0, &path))) {
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
    struct sr_conn_list_s *ptr, *prev;

    /* CONN LIST LOCK */
    if ((err_info = sr_mlock(&conn_proc.list_lock, SR_CONN_LIST_LOCK_TIMEOUT, __func__, NULL, NULL))) {
        return err_info;
    }

    ptr = conn_proc.list_head;
    prev = NULL;
    while (ptr) {
        if (cid == ptr->cid) {
            /* remove the entry from the list */
            if (!prev) {
                conn_proc.list_head = ptr->_next;
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
    sr_munlock(&conn_proc.list_lock);

    /* remove the lockfile as well */
    if ((err_info = sr_path_conn_lockfile(cid, 0, &path))) {
        return err_info;
    }
    if (unlink(path)) {
        SR_ERRINFO_SYSERRNO(&err_info, "unlink");
    }
    free(path);

    return err_info;
}

sr_error_info_t *
sr_shmmain_open(sr_shm_t *shm, int *created)
{
    sr_error_info_t *err_info = NULL;
    sr_main_shm_t *main_shm;
    char *shm_name = NULL, buf[128];
    int creat = 0;

    if ((err_info = sr_path_main_shm(&shm_name))) {
        goto cleanup;
    }

    /* try to open the shared memory */
    shm->fd = sr_open(shm_name, O_RDWR, SR_SHM_PERM);
    if ((shm->fd == -1) && (errno == ENOENT)) {
        if (!created) {
            /* we do not want to create the memory now */
            goto cleanup;
        }

        /* make sure the directory exists */
        strcpy(buf, SR_SHM_DIR);
        if ((err_info = sr_mkpath(buf, SR_DIR_PERM))) {
            goto cleanup;
        }

        /* create shared memory */
        shm->fd = sr_open(shm_name, O_RDWR | O_CREAT | O_EXCL, SR_SHM_PERM);
        creat = 1;
    }
    if (shm->fd == -1) {
        sr_errinfo_new(&err_info, SR_ERR_SYS, "Failed to open main shared memory (%s).", strerror(errno));
        goto cleanup;
    }

    /* map it with proper size */
    if ((err_info = sr_shm_remap(shm, creat ? sizeof *main_shm : 0))) {
        goto cleanup;
    }

    main_shm = (sr_main_shm_t *)shm->addr;

    /* main_shm can never be NULL */
    assert(main_shm);

    if (creat) {
        /* init the memory */
        main_shm->shm_ver = SR_SHM_VER;
        if ((err_info = sr_mutex_init(&main_shm->ext_lock, 1))) {
            goto cleanup;
        }
        if ((err_info = sr_rwlock_init(&main_shm->context_lock, 1))) {
            goto cleanup;
        }
        if ((err_info = sr_mutex_init(&main_shm->lydmods_lock, 1))) {
            goto cleanup;
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
            goto cleanup;
        }
    }

cleanup:
    if (err_info) {
        if (creat) {
            /* tried to create but could not setup fully, remove improper shm file */
            unlink(shm_name);
        }
        sr_shm_clear(shm);
    } else if (created) {
        *created = creat;
    }
    free(shm_name);
    return err_info;
}
