/**
 * @file shm_ext.c
 * @author Michal Vasko <mvasko@cesnet.cz>
 * @brief ext SHM routines
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
#include <fcntl.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#include <libyang/libyang.h>

#include "common.h"
#include "compat.h"
#include "log.h"

sr_error_info_t *
sr_shmext_conn_remap_lock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    size_t shm_file_size;

    if (ext_lock) {
        /* EXT LOCK */
        if ((err_info = sr_mlock(&SR_CONN_MAIN_SHM(conn)->ext_lock, SR_EXT_LOCK_TIMEOUT, func, NULL, NULL))) {
            return err_info;
        }
    }

    /* REMAP LOCK */
    if ((err_info = sr_rwlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func, NULL, NULL))) {
        goto error_ext_unlock;
    }

    /* remap ext SHM */
    if (mode == SR_LOCK_WRITE) {
        /* we have WRITE lock, it is safe */
        if ((err_info = sr_shm_remap(&conn->ext_shm, 0))) {
            goto error_ext_remap_unlock;
        }
    } else {
        if ((err_info = sr_file_get_size(conn->ext_shm.fd, &shm_file_size))) {
            goto error_ext_remap_unlock;
        }
        if (shm_file_size != conn->ext_shm.size) {
            /* ext SHM size changed and we need to remap it */
            if (mode == SR_LOCK_READ_UPGR) {
                /* REMAP WRITE LOCK UPGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                        func, NULL, NULL))) {
                    goto error_ext_remap_unlock;
                }
            } else {
                /* REMAP READ UNLOCK */
                sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, func);
                /* REMAP WRITE LOCK */
                if ((err_info = sr_rwlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                        func, NULL, NULL))) {
                    goto error_ext_unlock;
                }
            }

            /* remap SHM */
            if ((err_info = sr_shm_remap(&conn->ext_shm, 0))) {
                mode = SR_LOCK_WRITE;
                goto error_ext_remap_unlock;
            }

            /* do not release the lock anymore because ext SHM could be again remapped */
            if (mode == SR_LOCK_READ_UPGR) {
                /* REMAP READ UPGR LOCK DOWNGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ_UPGR,
                        conn->cid, func, NULL, NULL))) {
                    mode = SR_LOCK_WRITE;
                    goto error_ext_remap_unlock;
                }
            } else {
                /* REMAP READ LOCK DOWNGRADE */
                if ((err_info = sr_rwrelock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, SR_LOCK_READ,
                        conn->cid, func, NULL, NULL))) {
                    mode = SR_LOCK_WRITE;
                    goto error_ext_remap_unlock;
                }
            }
        } /* else no remapping needed */
    }

    return NULL;

error_ext_remap_unlock:
    /* REMAP UNLOCK */
    sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func);

error_ext_unlock:
    if (ext_lock) {
        /* EXT UNLOCK */
        sr_munlock(&SR_CONN_MAIN_SHM(conn)->ext_lock);
    }
    return err_info;
}

void
sr_shmext_conn_remap_unlock(sr_conn_ctx_t *conn, sr_lock_mode_t mode, int ext_lock, const char *func)
{
    sr_error_info_t *err_info = NULL;
    sr_ext_hole_t *iter, *last = NULL;
    uint32_t last_size;
    size_t shm_file_size;

    /* make ext SHM smaller if there is a memory hole at its end */
    if ((mode == SR_LOCK_WRITE) && ext_lock) {
        while ((iter = sr_ext_hole_next(last, SR_CONN_EXT_SHM(conn)))) {
            last = iter;
        }

        if (last && (((char *)last - conn->ext_shm.addr) + last->size == (signed)conn->ext_shm.size)) {
            if ((err_info = sr_file_get_size(conn->ext_shm.fd, &shm_file_size))) {
                goto cleanup_unlock;
            }

            /* remove the hole */
            last_size = last->size;
            sr_ext_hole_del(SR_CONN_EXT_SHM(conn), last);

            /* remap (and truncate) ext SHM */
            if ((err_info = sr_shm_remap(&conn->ext_shm, shm_file_size - last_size))) {
                goto cleanup_unlock;
            }
        }
    }

cleanup_unlock:
    /* REMAP UNLOCK */
    sr_rwunlock(&conn->ext_remap_lock, SR_CONN_REMAP_LOCK_TIMEOUT, mode, conn->cid, func);

    if (ext_lock) {
        /* EXT UNLOCK */
        sr_munlock(&SR_CONN_MAIN_SHM(conn)->ext_lock);
    }

    sr_errinfo_free(&err_info);
}

/**
 * @brief Item holding information about a SHM object for debug printing.
 */
struct shm_item {
    off_t start;
    size_t size;
    char *name;
};

/**
 * @brief Comparator for SHM print item qsort.
 *
 * @param[in] ptr1 First value pointer.
 * @param[in] ptr2 Second value pointer.
 * @return Less than, equal to, or greater than 0 if the first value is found
 * to be less than, equal to, or greater to the second value.
 */
static int
sr_shmext_print_cmp(const void *ptr1, const void *ptr2)
{
    struct shm_item *item1, *item2;

    item1 = (struct shm_item *)ptr1;
    item2 = (struct shm_item *)ptr2;

    if (item1->start < item2->start) {
        return -1;
    } else if (item1->start > item2->start) {
        return 1;
    }
    return 0;
}

/**
 * @brief Add new item for ext SHM print.
 *
 * @param[in,out] items Items array.
 * @param[in,out] item_count Count of @p items.
 * @param[in] start Start offset of the new item.
 * @param[in] size Size of the new item.
 * @param[in] name_format Name format string of the new item.
 * @param[in] ... Parameters of @p name_format.
 * @return SR_ERR value.
 */
static int
sr_shmext_print_add_item(struct shm_item **items, size_t *item_count, off_t start, size_t size,
        const char *name_format, ...)
{
    va_list ap;
    int rc;

    *items = sr_realloc(*items, (*item_count + 1) * sizeof **items);
    if (!*items) {
        return SR_ERR_NO_MEMORY;
    }

    (*items)[*item_count].start = start;
    (*items)[*item_count].size = size;

    va_start(ap, name_format);
    rc = vasprintf(&((*items)[*item_count].name), name_format, ap);
    va_end(ap);
    if (rc == -1) {
        return SR_ERR_NO_MEMORY;
    }

    ++(*item_count);
    return SR_ERR_OK;
}

void
sr_shmext_print(sr_main_shm_t *main_shm, sr_shm_t *shm_ext)
{
    sr_mod_t *shm_mod;
    off_t cur_off;
    sr_mod_change_sub_t *change_subs;
    sr_mod_oper_sub_t *oper_subs;
    sr_rpc_t *shm_rpc;
    sr_mod_rpc_sub_t *rpc_subs;
    struct shm_item *items = NULL;
    size_t idx, i, j, item_count = 0, printed;
    sr_datastore_t ds;
    int msg_len = 0;
    char *msg;
    sr_ext_hole_t *hole;
    sr_ext_shm_t *ext_shm = (sr_ext_shm_t *)shm_ext->addr;

    if ((stderr_ll < SR_LL_DBG) && (syslog_ll < SR_LL_DBG) && !log_cb) {
        /* nothing to print */
        return;
    }

    /* the structure itself */
    if (sr_shmext_print_add_item(&items, &item_count, 0, SR_SHM_SIZE(sizeof(sr_ext_shm_t)), "ext structure")) {
        goto error;
    }

    /* add all memory holes */
    for (hole = sr_ext_hole_next(NULL, ext_shm); hole; hole = sr_ext_hole_next(hole, ext_shm)) {
        if (sr_shmext_print_add_item(&items, &item_count, ((char *)hole) - shm_ext->addr, hole->size,
                "memory hole (size %" PRIu32 ")", hole->size)) {
            goto error;
        }
    }

    for (idx = 0; idx < main_shm->mod_count; ++idx) {
        shm_mod = SR_SHM_MOD_IDX(main_shm, idx);

        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            if (shm_mod->change_sub[ds].sub_count) {
                /* add change subscriptions */
                if (sr_shmext_print_add_item(&items, &item_count, shm_mod->change_sub[ds].subs,
                        SR_SHM_SIZE(shm_mod->change_sub[ds].sub_count * sizeof *change_subs),
                        "%s change subs (%" PRIu32 ", mod \"%s\")", sr_ds2str(ds), shm_mod->change_sub[ds].sub_count,
                        ((char *)main_shm) + shm_mod->name)) {
                    goto error;
                }

                /* add xpaths */
                change_subs = (sr_mod_change_sub_t *)(shm_ext->addr + shm_mod->change_sub[ds].subs);
                for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
                    if (change_subs[i].xpath) {
                        if (sr_shmext_print_add_item(&items, &item_count, change_subs[i].xpath,
                                sr_strshmlen(shm_ext->addr + change_subs[i].xpath),
                                "%s change sub xpath (\"%s\", mod \"%s\")", sr_ds2str(ds),
                                shm_ext->addr + change_subs[i].xpath, ((char *)main_shm) + shm_mod->name)) {
                            goto error;
                        }
                    }
                }
            }
        }

        if (shm_mod->oper_sub_count) {
            /* add oper subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->oper_subs,
                    SR_SHM_SIZE(shm_mod->oper_sub_count * sizeof *oper_subs), "oper subs (%" PRIu32 ", mod \"%s\")",
                    shm_mod->oper_sub_count, ((char *)main_shm) + shm_mod->name)) {
                goto error;
            }

            /* add xpaths */
            oper_subs = (sr_mod_oper_sub_t *)(shm_ext->addr + shm_mod->oper_subs);
            for (i = 0; i < shm_mod->oper_sub_count; ++i) {
                if (sr_shmext_print_add_item(&items, &item_count, oper_subs[i].xpath,
                        sr_strshmlen(shm_ext->addr + oper_subs[i].xpath), "oper sub xpath (\"%s\", mod \"%s\")",
                        shm_ext->addr + oper_subs[i].xpath, ((char *)main_shm) + shm_mod->name)) {
                    goto error;
                }
            }
        }

        shm_rpc = (sr_rpc_t *)(((char *)main_shm) + shm_mod->rpcs);
        for (i = 0; i < shm_mod->rpc_count; ++i) {
            if (shm_rpc[i].sub_count) {
                /* add RPC subscriptions */
                if (sr_shmext_print_add_item(&items, &item_count, shm_rpc[i].subs,
                        SR_SHM_SIZE(shm_rpc[i].sub_count * sizeof *rpc_subs), "rpc subs (%" PRIu32 ", path \"%s\")",
                        shm_rpc[i].sub_count, ((char *)main_shm) + shm_rpc[i].path)) {
                    goto error;
                }

                rpc_subs = (sr_mod_rpc_sub_t *)(shm_ext->addr + shm_rpc[i].subs);
                for (j = 0; j < shm_rpc[i].sub_count; ++j) {
                    /* add RPC subscription XPath */
                    if (sr_shmext_print_add_item(&items, &item_count, rpc_subs[j].xpath,
                            sr_strshmlen(shm_ext->addr + rpc_subs[j].xpath), "rpc sub xpath (\"%s\", path \"%s\")",
                            shm_ext->addr + rpc_subs[j].xpath, ((char *)main_shm) + shm_rpc[i].path)) {
                        goto error;
                    }
                }
            }
        }

        if (shm_mod->notif_sub_count) {
            /* add notif subscriptions */
            if (sr_shmext_print_add_item(&items, &item_count, shm_mod->notif_subs,
                    SR_SHM_SIZE(shm_mod->notif_sub_count * sizeof(sr_mod_notif_sub_t)),
                    "notif subs (%" PRIu32 ", mod \"%s\")", shm_mod->notif_sub_count, ((char *)main_shm) + shm_mod->name)) {
                goto error;
            }
        }
    }

    /* sort all items */
    qsort(items, item_count, sizeof *items, sr_shmext_print_cmp);

    /* print it */
    printed = 0;
    for (i = 0; i < item_count; ++i) {
        printed += sr_sprintf(&msg, &msg_len, printed, "%06jd-%06jd [%6zu]: %s\n",
                (intmax_t)items[i].start, (intmax_t)(items[i].start + items[i].size), items[i].size, items[i].name);
    }

    /* print all the information about SHM */
    SR_LOG_DBG("#SHM:\n%s", msg);
    free(msg);

    /* fail on an assert if something is wrong */
    cur_off = 0;
    for (i = 0; i < item_count; ++i) {
        if (i < item_count - 1) {
            /* checks on 2 following items */
            assert(items[i].start != items[i + 1].start);
            assert((items[i].start > items[i + 1].start) ||
                    (items[i].start + items[i].size <= (unsigned)items[i + 1].start));
            assert((items[i].start < items[i + 1].start) ||
                    (items[i + 1].start + items[i + 1].size <= (unsigned)items[i].start));
        }

        /* check item start */
        assert(items[i].start == cur_off);
        cur_off += items[i].size;

        /* check alignment */
        assert(items[i].size == SR_SHM_SIZE(items[i].size));
        assert((unsigned)items[i].start == SR_SHM_SIZE(items[i].start));

        /* free name */
        free(items[i].name);
    }
    free(items);

    /* check that no item exists after the mapped segment */
    assert((unsigned)cur_off == shm_ext->size);
    return;

error:
    for (i = 0; i < item_count; ++i) {
        free(items[i].name);
    }
    free(items);
}

sr_error_info_t *
sr_shmext_change_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock, sr_datastore_t ds,
        uint32_t sub_id, const char *xpath, uint32_t priority, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    assert((has_lock == SR_LOCK_NONE) || (has_lock == SR_LOCK_WRITE));

    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    if (sub_opts & SR_SUBSCR_UPDATE) {
        /* check that there is not already an update subscription with the same priority */
        shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
        for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
            if ((shm_sub[i].opts & SR_SUBSCR_UPDATE) && (shm_sub[i].priority == priority)) {
                if (!sr_conn_is_alive(shm_sub[i].cid)) {
                    /* subscription is dead, recover it */
                    if ((err_info = sr_shmext_change_sub_stop(conn, shm_mod, ds, i, 1, SR_LOCK_WRITE, 1))) {
                        goto cleanup_changesub_ext_unlock;
                    }

                    /* there could not be more of such subscriptions, we have the right index for insertion */
                    break;
                }

                sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG,
                        "There already is an \"update\" subscription on module \"%s\" with priority %" PRIu32 " for %s DS.",
                        conn->main_shm.addr + shm_mod->name, priority, sr_ds2str(ds));
                goto cleanup_changesub_ext_unlock;
            }
        }
    }

    SR_LOG_DBG("#SHM before (adding change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count,
            0, sizeof *shm_sub, -1, (void **)&shm_sub, xpath ? sr_strshmlen(xpath) : 0, &xpath_off))) {
        goto cleanup_changesub_ext_unlock;
    }

    /* fill new subscription */
    if (xpath) {
        strcpy(conn->ext_shm.addr + xpath_off, xpath);
        shm_sub->xpath = xpath_off;
    } else {
        shm_sub->xpath = 0;
    }
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_mod->change_sub[ds].sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1,
                sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_changesub_ext_unlock;
        }
    }

    /* success */

cleanup_changesub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_changesub_unlock:
    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_modify(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t sub_id, const char *xpath)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;
    int cur_size, new_size;

    /* CHANGE SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
            __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->change_sub[ds].sub_count, err_info, cleanup_changesub_ext_unlock);

    SR_LOG_DBG("#SHM before (modifying change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* allocate memory for the new xpath, if any */
    cur_size = shm_sub[i].xpath ? strlen(conn->ext_shm.addr + shm_sub[i].xpath) + 1 : 0;
    new_size = xpath ? strlen(xpath) + 1 : 0;
    if ((err_info = sr_shmrealloc(&conn->ext_shm, &shm_sub[i].xpath, 1, cur_size, new_size))) {
        goto cleanup_changesub_ext_unlock;
    }

    /* fill new xpath */
    if (xpath) {
        strcpy(conn->ext_shm.addr + shm_sub[i].xpath, xpath);
    } else {
        shm_sub[i].xpath = 0;
    }

    SR_LOG_DBG("#SHM after (modifying change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* success */

cleanup_changesub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_changesub_unlock:
    /* CHANGE SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Free change subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] ds Subscription datastore.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_change_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);

    SR_LOG_DBG("#SHM before (removing change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription and its xpath, if any */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->change_sub[ds].subs, &shm_mod->change_sub[ds].sub_count,
            sizeof *shm_sub, del_idx, shm_sub[del_idx].xpath ? sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath) : 0,
            shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing change sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_mod->change_sub[ds].sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_lock_mode_t has_lock, sr_datastore_t ds,
        uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    assert((has_lock == SR_LOCK_NONE) || (has_lock == SR_LOCK_WRITE));

    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->change_sub[ds].sub_count) {
        /* subscription not found */
        goto cleanup_changesub_ext_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_change_sub_free(conn, shm_mod, ds, i))) {
        goto cleanup_changesub_ext_unlock;
    }

cleanup_changesub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_changesub_unlock:
    if (has_lock == SR_LOCK_NONE) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_change_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, sr_datastore_t ds, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_change_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* CHANGE SUB READ UNLOCK */
            sr_rwunlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

        /* CHANGE SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\" %s change subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, sr_ds2str(ds), shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((tmp_err = sr_shmext_change_sub_free(conn, shm_mod, ds, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* CHANGE SUB READ LOCK DOWNGRADE */
            if ((tmp_err = sr_rwrelock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid,
                    __func__, NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }

            /* EXT READ LOCK */
            if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* CHANGE SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, const char *xpath,
        sr_mod_oper_sub_type_t sub_type, int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_oper_sub_t *shm_sub;
    size_t new_len, cur_len;
    uint32_t i;

    assert(xpath && sub_type);

    /* OPER SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* check that this exact subscription does not exist yet while finding its position */
    new_len = sr_xpath_len_no_predicates(xpath);
    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        cur_len = sr_xpath_len_no_predicates(conn->ext_shm.addr + shm_sub[i].xpath);
        if (cur_len > new_len) {
            /* we can insert it at i-th position */
            break;
        }

        if ((cur_len == new_len) && !strcmp(conn->ext_shm.addr + shm_sub[i].xpath, xpath)) {
            if (!sr_conn_is_alive(shm_sub[i].cid)) {
                /* subscription is dead, recover it */
                if ((err_info = sr_shmext_oper_sub_stop(conn, shm_mod, i, 1, SR_LOCK_WRITE, 1))) {
                    goto cleanup_opersub_ext_unlock;
                }

                /* there could not be more of such subscriptions, we have the right index for insertion */
                break;
            }

            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG,
                    "Operational data provider subscription for \"%s\" on \"%s\" already exists.",
                    conn->main_shm.addr + shm_mod->name, xpath);
            goto cleanup_opersub_ext_unlock;
        }
    }

    SR_LOG_DBG("#SHM before (adding oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* allocate new subscription and its xpath, if any */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->oper_subs, &shm_mod->oper_sub_count, 0, sizeof *shm_sub,
            i, (void **)&shm_sub, sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup_opersub_ext_unlock;
    }

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->sub_type = sub_type;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* create the sub SHM while still holding the locks */
    if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, "oper", sr_str_hash(xpath),
            sizeof(sr_sub_shm_t)))) {
        goto cleanup_opersub_ext_unlock;
    }

cleanup_opersub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_opersub_unlock:
    /* OPER SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Free operational subscription data from ext SHM, remove sub SHM.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_oper_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_sub;

    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);

    /* unlink the sub SHM (first, so that we can use xpath) */
    if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub[del_idx].xpath)))) {
        goto cleanup;
    }

    /* unlink the sub data SHM */
    if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, "oper",
            sr_str_hash(conn->ext_shm.addr + shm_sub[del_idx].xpath)))) {
        goto cleanup;
    }

    SR_LOG_DBG("#SHM before (removing oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->oper_subs, &shm_mod->oper_sub_count, sizeof *shm_sub, del_idx,
            sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath), shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing oper sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_oper_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_oper_sub_t *shm_sub;
    uint32_t i;

    /* OPER SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL,
            NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->oper_sub_count) {
        /* no matching subscription found */
        goto cleanup_opersub_ext_unlock;
    }

    /* delete the subscription */
    if ((err_info = sr_shmext_oper_sub_free(conn, shm_mod, i))) {
        goto cleanup_opersub_ext_unlock;
    }

cleanup_opersub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_opersub_unlock:
    /* OPER SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_oper_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* OPER SUB READ UNLOCK */
            sr_rwunlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

        /* OPER SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\" operational subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((tmp_err = sr_shmext_oper_sub_free(conn, shm_mod, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* OPER SUB READ LOCK DOWNGRADE */
            if ((err_info = sr_rwrelock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                    NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }

            /* EXT READ LOCK */
            if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* OPER SUB WRITE UNLOCK */
            sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_add(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id, uint32_t evpipe_num,
        struct timespec *listen_since)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        return err_info;
    }

    /* if a notification is sent now, once it gets the lock, this subscription will already be listening */
    sr_time_get(listen_since, 0);

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    SR_LOG_DBG("#SHM before (adding notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* add new item */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, 0,
            sizeof *shm_sub, -1, (void **)&shm_sub, 0, NULL))) {
        goto cleanup_notifsub_ext_unlock;
    }

    /* fill new subscription */
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_mod->notif_sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        if ((err_info = sr_shmsub_create(conn->main_shm.addr + shm_mod->name, "notif", -1, sizeof(sr_sub_shm_t)))) {
            goto cleanup_notifsub_ext_unlock;
        }
    }

cleanup_notifsub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_notifsub_unlock:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

/**
 * @brief Free notification subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_mod SHM module with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_notif_sub_free(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;

    SR_LOG_DBG("#SHM before (removing notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_mod->notif_subs, &shm_mod->notif_sub_count, sizeof(sr_mod_notif_sub_t),
            del_idx, 0, 0);

    SR_LOG_DBG("#SHM after (removing notif sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_mod->notif_sub_count) {
        /* unlink the sub SHM */
        if ((err_info = sr_shmsub_unlink(conn->main_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(conn->main_shm.addr + shm_mod->name, "notif", -1))) {
            goto cleanup;
        }
    }

cleanup:
    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_del(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_notif_sub_t *shm_sub;
    uint32_t i;

    /* NOTIF SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL,
            NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_mod->notif_sub_count) {
        /* no matching subscription found */
        goto cleanup_notifsub_ext_unlock;
    }

    /* remove the subscription */
    if ((err_info = sr_shmext_notif_sub_free(conn, shm_mod, i))) {
        goto cleanup_notifsub_ext_unlock;
    }

cleanup_notifsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_notifsub_unlock:
    /* NOTIF SUB WRITE UNLOCK */
    sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_stop(sr_conn_ctx_t *conn, sr_mod_t *shm_mod, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_notif_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

        /* NOTIF SUB READ UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
    }

    /* NOTIF SUB WRITE LOCK */
    if ((tmp_err = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
            NULL, NULL))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    /* EXT READ LOCK */
    if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    if (recovery) {
        SR_LOG_WRN("Recovering module \"%s\"notification subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_mod->name, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((tmp_err = sr_shmext_notif_sub_free(conn, shm_mod, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks == SR_LOCK_READ) {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* NOTIF SUB READ LOCK DOWNGRADE */
        if ((tmp_err = sr_rwrelock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    } else {
        /* EXT READ UNLOCK */
        sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

        /* NOTIF SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_add(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t sub_id, const char *xpath, uint32_t priority,
        int sub_opts, uint32_t evpipe_num)
{
    sr_error_info_t *err_info = NULL;
    off_t xpath_off;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;
    char *mod_name = NULL;

    assert(xpath);

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT WRITE LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_WRITE, 1, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* check that this exact subscription does not exist yet */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub[i].priority == priority) {
            if (!sr_conn_is_alive(shm_sub[i].cid)) {
                /* subscription is dead, recover it */
                if ((err_info = sr_shmext_rpc_sub_stop(conn, shm_rpc, i, 1, SR_LOCK_WRITE, 1))) {
                    goto cleanup_rpcsub_ext_unlock;
                }

                /* there could not be more of such subscriptions */
                break;
            }

            sr_errinfo_new(&err_info, SR_ERR_INVAL_ARG, "RPC subscription for \"%s\" with priority %" PRIu32
                    " already exists.", conn->main_shm.addr + shm_rpc->path, priority);
            goto cleanup_rpcsub_ext_unlock;
        }
    }

    SR_LOG_DBG("#SHM before (adding rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* add new subscription with its xpath */
    if ((err_info = sr_shmrealloc_add(&conn->ext_shm, &shm_rpc->subs, &shm_rpc->sub_count, 0, sizeof *shm_sub, -1,
            (void **)&shm_sub, sr_strshmlen(xpath), &xpath_off))) {
        goto cleanup_rpcsub_ext_unlock;
    }

    /* fill new subscription */
    strcpy(conn->ext_shm.addr + xpath_off, xpath);
    shm_sub->xpath = xpath_off;
    shm_sub->priority = priority;
    shm_sub->opts = sub_opts;
    shm_sub->sub_id = sub_id;
    shm_sub->evpipe_num = evpipe_num;
    ATOMIC_STORE_RELAXED(shm_sub->suspended, 0);
    shm_sub->cid = conn->cid;

    SR_LOG_DBG("#SHM after (adding rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (shm_rpc->sub_count == 1) {
        /* create the sub SHM while still holding the locks */
        mod_name = sr_get_first_ns(conn->main_shm.addr + shm_rpc->path);
        if ((err_info = sr_shmsub_create(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path),
                sizeof(sr_multi_sub_shm_t)))) {
            goto cleanup_rpcsub_ext_unlock;
        }
    }

cleanup_rpcsub_ext_unlock:
    /* EXT WRITE UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_WRITE, 1, __func__);

cleanup_rpcsub_unlock:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    free(mod_name);
    return err_info;
}

/**
 * @brief Free RPC/action subscription data from ext SHM, remove sub SHM if not used anymore.
 *
 * @param[in] conn Connection to use.
 * @param[in] shm_rpc SHM RPC with subscriptions.
 * @param[in] del_idx Index of the subscription to free.
 * @return err_info, NULL on success.
 */
static sr_error_info_t *
sr_shmext_rpc_sub_free(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t del_idx)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    char *mod_name = NULL;

    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);

    SR_LOG_DBG("#SHM before (removing rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    /* free the subscription */
    sr_shmrealloc_del(&conn->ext_shm, &shm_rpc->subs, &shm_rpc->sub_count, sizeof *shm_sub, del_idx,
            sr_strshmlen(conn->ext_shm.addr + shm_sub[del_idx].xpath), shm_sub[del_idx].xpath);

    SR_LOG_DBG("#SHM after (removing rpc sub)");
    sr_shmext_print(SR_CONN_MAIN_SHM(conn), &conn->ext_shm);

    if (!shm_rpc->sub_count) {
        /* unlink the sub SHM */
        mod_name = sr_get_first_ns(conn->main_shm.addr + shm_rpc->path);
        if ((err_info = sr_shmsub_unlink(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path)))) {
            goto cleanup;
        }

        /* unlink the sub data SHM */
        if ((err_info = sr_shmsub_data_unlink(mod_name, "rpc", sr_str_hash(conn->main_shm.addr + shm_rpc->path)))) {
            goto cleanup;
        }
    }

cleanup:
    free(mod_name);
    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_del(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t sub_id)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;

    /* RPC SUB WRITE LOCK */
    if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__, NULL, NULL))) {
        return err_info;
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* find the subscription */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    if (i == shm_rpc->sub_count) {
        /* no matching subscription found */
        goto cleanup_rpcsub_ext_unlock;
    }

    /* free the subscription */
    if ((err_info = sr_shmext_rpc_sub_free(conn, shm_rpc, i))) {
        goto cleanup_rpcsub_ext_unlock;
    }

cleanup_rpcsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

cleanup_rpcsub_unlock:
    /* RPC SUB WRITE UNLOCK */
    sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_stop(sr_conn_ctx_t *conn, sr_rpc_t *shm_rpc, uint32_t del_idx, int del_evpipe,
        sr_lock_mode_t has_locks, int recovery)
{
    sr_error_info_t *err_info = NULL, *tmp_err;
    sr_mod_rpc_sub_t *shm_sub;
    char *path;
    uint32_t evpipe_num;

    assert((has_locks == SR_LOCK_WRITE) || (has_locks == SR_LOCK_READ) || (has_locks == SR_LOCK_NONE));

    /* get sub write lock keeping the lock order */
    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

            /* RPC SUB READ UNLOCK */
            sr_rwunlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__);
        }

        /* RPC SUB WRITE LOCK */
        if ((tmp_err = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid, __func__,
                NULL, NULL))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }

        /* EXT READ LOCK */
        if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 1, __func__))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
    }

    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    if (recovery) {
        SR_LOG_WRN("Recovering RPC/action \"%s\" subscription of CID %" PRIu32 ".",
                conn->main_shm.addr + shm_rpc->path, shm_sub[del_idx].cid);
    }
    evpipe_num = shm_sub[del_idx].evpipe_num;

    /* remove the subscription */
    if ((tmp_err = sr_shmext_rpc_sub_free(conn, shm_rpc, del_idx))) {
        sr_errinfo_merge(&err_info, tmp_err);
    }

    if (has_locks != SR_LOCK_WRITE) {
        if (has_locks == SR_LOCK_READ) {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* RPC SUB READ LOCK DOWNGRADE */
            if ((err_info = sr_rwrelock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_READ, conn->cid, __func__,
                    NULL, NULL))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }

            /* EXT READ LOCK */
            if ((tmp_err = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
                sr_errinfo_merge(&err_info, tmp_err);
            }
        } else {
            /* EXT READ UNLOCK */
            sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 1, __func__);

            /* RPC SUB WRITE UNLOCK */
            sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
        }
    }

    if (del_evpipe) {
        /* delete the evpipe file, it could have been already deleted by removing other subscription
         * from the same structure */
        if ((tmp_err = sr_path_evpipe(evpipe_num, &path))) {
            sr_errinfo_merge(&err_info, tmp_err);
        }
        unlink(path);
        free(path);
    }

    return err_info;
}

void
sr_shmext_recover_sub_all(sr_conn_ctx_t *conn)
{
    sr_error_info_t *err_info = NULL;
    sr_datastore_t ds;
    sr_mod_t *shm_mod;
    sr_rpc_t *shm_rpc;
    uint32_t i, j, count;

    /* go through all the modules, RPCs and recover their subscriptions */
    for (i = 0; i < SR_CONN_MAIN_SHM(conn)->mod_count; ++i) {
        shm_mod = SR_SHM_MOD_IDX(conn->main_shm.addr, i);
        for (ds = 0; ds < SR_DS_COUNT; ++ds) {
            for (count = shm_mod->change_sub[ds].sub_count; count; --count) {
                if ((err_info = sr_shmext_change_sub_stop(conn, shm_mod, ds, count - 1, 1, SR_LOCK_NONE, 1))) {
                    sr_errinfo_free(&err_info);
                }
            }
        }

        shm_rpc = (sr_rpc_t *)(conn->main_shm.addr + shm_mod->rpcs);
        for (j = 0; j < shm_mod->rpc_count; ++j) {
            for (count = shm_rpc[j].sub_count; count; --count) {
                if ((err_info = sr_shmext_rpc_sub_stop(conn, &shm_rpc[j], count - 1, 1, SR_LOCK_NONE, 1))) {
                    sr_errinfo_free(&err_info);
                }
            }
        }

        for (count = shm_mod->oper_sub_count; count; --count) {
            if ((err_info = sr_shmext_oper_sub_stop(conn, shm_mod, count - 1, 1, SR_LOCK_NONE, 1))) {
                sr_errinfo_free(&err_info);
            }
        }

        for (count = shm_mod->notif_sub_count; count; --count) {
            if ((err_info = sr_shmext_notif_sub_stop(conn, shm_mod, count - 1, 1, SR_LOCK_NONE, 1))) {
                sr_errinfo_free(&err_info);
            }
        }
    }
}

sr_error_info_t *
sr_shmext_change_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, sr_datastore_t ds, uint32_t sub_id,
        int set_suspended, int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_change_sub_t *shm_sub;
    uint32_t i;

    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* CHANGE SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->change_sub[ds].lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_changesub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_change_sub_t *)(conn->ext_shm.addr + shm_mod->change_sub[ds].subs);
    for (i = 0; i < shm_mod->change_sub[ds].sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->change_sub[ds].sub_count, err_info, cleanup_changesub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Change subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_changesub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Change subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_changesub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_changesub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_changesub_unlock:
    if (set_suspended > -1) {
        /* CHANGE SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->change_sub[ds].lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_oper_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int set_suspended,
        int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_oper_sub_t *shm_sub;
    uint32_t i;

    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* OPER SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->oper_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_opersub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_oper_sub_t *)(conn->ext_shm.addr + shm_mod->oper_subs);
    for (i = 0; i < shm_mod->oper_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->oper_sub_count, err_info, cleanup_opersub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_opersub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Operational subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_opersub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_opersub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_opersub_unlock:
    if (set_suspended > -1) {
        /* OPER SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->oper_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_notif_sub_suspended(sr_conn_ctx_t *conn, const char *mod_name, uint32_t sub_id, int set_suspended,
        int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_mod_t *shm_mod;
    sr_mod_notif_sub_t *shm_sub;
    uint32_t i;

    shm_mod = sr_shmmain_find_module(SR_CONN_MAIN_SHM(conn), mod_name);
    SR_CHECK_INT_RET(!shm_mod, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* NOTIF SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_mod->notif_lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_notifsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_notif_sub_t *)(conn->ext_shm.addr + shm_mod->notif_subs);
    for (i = 0; i < shm_mod->notif_sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_mod->notif_sub_count, err_info, cleanup_notifsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Notification subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_notifsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "Notification subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_notifsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_notifsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_notifsub_unlock:
    if (set_suspended > -1) {
        /* NOTIF SUB WRITE UNLOCK */
        sr_rwunlock(&shm_mod->notif_lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}

sr_error_info_t *
sr_shmext_rpc_sub_suspended(sr_conn_ctx_t *conn, const char *path, uint32_t sub_id, int set_suspended, int *get_suspended)
{
    sr_error_info_t *err_info = NULL;
    sr_rpc_t *shm_rpc;
    sr_mod_rpc_sub_t *shm_sub;
    uint32_t i;

    shm_rpc = sr_shmmain_find_rpc(SR_CONN_MAIN_SHM(conn), path);
    SR_CHECK_INT_RET(!shm_rpc, err_info);

    /* changing suspended technically modifies (adds/removes) subscriptions */
    if (set_suspended > -1) {
        /* RPC SUB WRITE LOCK */
        if ((err_info = sr_rwlock(&shm_rpc->lock, SR_SHMEXT_SUB_LOCK_TIMEOUT, SR_LOCK_WRITE, conn->cid,
                __func__, NULL, NULL))) {
            return err_info;
        }
    }

    /* EXT READ LOCK */
    if ((err_info = sr_shmext_conn_remap_lock(conn, SR_LOCK_READ, 0, __func__))) {
        goto cleanup_rpcsub_unlock;
    }

    /* find the subscription in ext SHM */
    shm_sub = (sr_mod_rpc_sub_t *)(conn->ext_shm.addr + shm_rpc->subs);
    for (i = 0; i < shm_rpc->sub_count; ++i) {
        if (shm_sub[i].sub_id == sub_id) {
            break;
        }
    }
    SR_CHECK_INT_GOTO(i == shm_rpc->sub_count, err_info, cleanup_rpcsub_ext_unlock);

    if (set_suspended > -1) {
        /* check whether the flag can be changed */
        if (set_suspended && ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "RPC/action subscription with ID %" PRIu32
                    " already suspended.", sub_id);
            goto cleanup_rpcsub_ext_unlock;
        } else if (!set_suspended && !ATOMIC_LOAD_RELAXED(shm_sub[i].suspended)) {
            sr_errinfo_new(&err_info, SR_ERR_UNSUPPORTED, "RPC/action subscription with ID %" PRIu32
                    " not suspended.", sub_id);
            goto cleanup_rpcsub_ext_unlock;
        }

        /* set the flag */
        ATOMIC_STORE_RELAXED(shm_sub[i].suspended, set_suspended);
    }

    if (get_suspended) {
        /* read the flag */
        *get_suspended = ATOMIC_LOAD_RELAXED(shm_sub[i].suspended);
    }

cleanup_rpcsub_ext_unlock:
    /* EXT READ UNLOCK */
    sr_shmext_conn_remap_unlock(conn, SR_LOCK_READ, 0, __func__);

cleanup_rpcsub_unlock:
    if (set_suspended > -1) {
        /* RPC SUB WRITE UNLOCK */
        sr_rwunlock(&shm_rpc->lock, 0, SR_LOCK_WRITE, conn->cid, __func__);
    }

    return err_info;
}
